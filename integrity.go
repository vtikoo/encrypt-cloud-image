// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	internal_exec "github.com/canonical/encrypt-cloud-image/internal/exec"
	"github.com/canonical/encrypt-cloud-image/internal/fs"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
	log "github.com/sirupsen/logrus"

	snapd_dmverity "github.com/snapcore/snapd/snap/integrity/dmverity"
)

const (
	verityPartitionNum = 2
)

type integrityOptions struct {
	Output string `short:"o" long:"output" description:"Output image path"`

	Positional struct {
		Input string `positional-arg-name:"Source image path (file or block device)"`
	} `positional-args:"true" required:"true"`
}

func (o *integrityOptions) Execute(_ []string) error {
	d := new(imageIntegrityProtector)
	return d.run(o)
}

func (o *integrityOptions) GetPositionalInput() string {
	return o.Positional.Input
}

func (o *integrityOptions) GetOutput() string {
	return o.Output
}

func sectorsFromBlocks(fsBlockCount uint64, fsBlockSize uint64) uint64 {
	fsSize := fsBlockCount * fsBlockSize
	// gpt.BlockSize corresponds to the sector size
	fsSectors := fsSize / gpt.BlockSize
	// partitions are aligned to 2048-sector boundaries
	return ((fsSectors-1)/2048 + 1) * 2048
}

type imageIntegrityProtector struct {
	encryptCloudImageBase

	opts            *integrityOptions
	failed          bool
	verityPartition *gpt.PartitionEntry
}

func (i *imageIntegrityProtector) prepareRootPartition() error {
	devPath := i.rootDevPath()

	if err := checkIntegrityExtFS(devPath); err != nil {
		return err
	}

	log.Infoln("shrinking fileystem on", devPath)
	if err := shrinkExtFS(devPath); err != nil {
		return fmt.Errorf("cannot shrink filesystem: %w", err)
	}

	// If the image has been booted before, filesystem errors that will
	// be corrected on boot might cause verity errors.
	log.Infoln("running checks on", devPath)
	if err := checkIntegrityExtFS(devPath); err != nil {
		return err
	}

	log.Infoln("resizing partition", devPath)

	fsBlockCount, fsBlockSize, err := fs.GetBlockInfo(devPath)
	if err != nil {
		return err
	}

	endingLBA := uint64(i.rootPartition.StartingLBA) + sectorsFromBlocks(fsBlockCount, fsBlockSize) - 1

	action := func() error {
		cmd := internal_exec.LoggedCommand("sgdisk",
			i.imagePath,
			"--delete",
			fmt.Sprintf("%d", i.rootPartition.Index),
			"--new",
			fmt.Sprintf("%d:%d:%d", i.rootPartition.Index, i.rootPartition.StartingLBA, endingLBA),
			"--partition-guid",
			fmt.Sprintf("%d:%s", i.rootPartition.Index, i.rootPartition.UniquePartitionGUID),
			"--typecode",
			fmt.Sprintf("%d:%s", i.rootPartition.Index, i.rootPartition.PartitionTypeGUID),
			"--change-name",
			fmt.Sprintf("%d:%s", i.rootPartition.Index, "cloudimg-rootfs"),
		)

		return cmd.Run()
	}

	if err := i.repartition(action); err != nil {
		return err
	}
	return i.syncIntegrityPartitionNodes()
}

func checkIntegrityExtFS(path string) error {
	err := internal_exec.LoggedCommand("e2fsck", "-p", "-f", path).Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil
	}
	return err
}

func (i *imageIntegrityProtector) createIntegrityDataForRootPartition() (string, string, error) {
	verityFilePath := filepath.Join(i.workingDirPath(), "rootfs.verity")

	log.Infoln("generating verity data for root partition")
	verityInfo, err := snapd_dmverity.Format(i.rootDevPath(), verityFilePath)
	if err != nil {
		return "", "", err
	}

	return verityInfo.RootHash, verityFilePath, nil
}

func (i *imageIntegrityProtector) createVerityPartition(size uint64) error {
	for _, partition := range i.partitions {
		if partition.Index == verityPartitionNum && partition != i.verity {
			return fmt.Errorf("refusing to replace occupied partition %d", verityPartitionNum)
		}
	}
	if i.verity != nil && i.verity.Index != verityPartitionNum {
		return fmt.Errorf("existing verity partition must have index %d", verityPartitionNum)
	}
	action := func() error {
		if i.verity != nil {
			log.Infoln("deleting existing verity partition")

			cmd := internal_exec.LoggedCommand("sgdisk",
				i.imagePath,
				"--delete",
				fmt.Sprintf("%d", verityPartitionNum),
			)

			if err := cmd.Run(); err != nil {
				return err
			}
		}

		log.Infoln("creating a new verity partition")

		// align to the next 2048-sector boundary
		verityPartitionStart := i.rootPartition.EndingLBA/2048*2048 + 2048

		cmd := internal_exec.LoggedCommand("sgdisk",
			i.imagePath,
			"--move-second-header",
			"--new",
			fmt.Sprintf("%d:%d:+%d", verityPartitionNum, verityPartitionStart, (size+gpt.BlockSize-1)/gpt.BlockSize),
			"--typecode",
			fmt.Sprintf("%d:%s", verityPartitionNum, rootVerityPartitionAmd64GUID),
			"--change-name",
			fmt.Sprintf("%d:%s", verityPartitionNum, "cloudimg-rootfs-verity"),
		)

		if err := cmd.Run(); err != nil {
			return err
		}

		return nil
	}

	if err := i.repartition(action); err != nil {
		return err
	}
	return i.syncIntegrityPartitionNodes()
}

func (i *imageIntegrityProtector) createOrUpdateVerityPartition(verityFilePath string) error {
	fi, err := os.Stat(verityFilePath)
	if err != nil {
		return err
	}
	veritySize := uint64(fi.Size())

	create := true
	if i.verity != nil {
		if verityPartitionFits(i.verity, veritySize) {
			create = false
		}
	}

	if create {
		if err = i.createVerityPartition(veritySize); err != nil {
			return err
		}
	}

	// Update verity partition

	cmd := internal_exec.LoggedCommand("dd",
		"if="+verityFilePath,
		"of="+i.verityDevPath(),
		"conv=nocreat",
	)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func verityPartitionFits(partition *gpt.PartitionEntry, size uint64) bool {
	if partition.EndingLBA < partition.StartingLBA {
		return false
	}
	return uint64(partition.EndingLBA-partition.StartingLBA+1)*gpt.BlockSize >= size
}

// These match the structs in snap-bootstrap
type ImageManifestPartition struct {
	GptLabel string `json:"label"`
	RootHash string `json:"root_hash"`
	ReadOnly bool   `json:"read_only"`
}

type ImageManifest struct {
	Partitions []ImageManifestPartition `json:"partitions"`
}

func (i *imageIntegrityProtector) syncIntegrityPartitionNodes() error {
	if err := internal_exec.LoggedCommand("blockdev", "--rereadpt", i.devPath).Run(); err != nil {
		return fmt.Errorf("cannot refresh integrity-image partition nodes: %w", err)
	}
	if err := internal_exec.LoggedCommand("udevadm", "settle").Run(); err != nil {
		return err
	}
	for _, partition := range i.partitions {
		devicePath := i.getDevPath(partition.Index)
		path := filepath.Join("/sys/class/block", filepath.Base(devicePath))
		var stat unix.Stat_t
		if err := unix.Stat(devicePath, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFBLK {
			return fmt.Errorf("%s is not a block device", devicePath)
		}
		expectedDevice, err := os.ReadFile(filepath.Join(path, "dev"))
		if err != nil {
			return err
		}
		actualDevice := fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Rdev)), unix.Minor(uint64(stat.Rdev)))
		if actualDevice != strings.TrimSpace(string(expectedDevice)) {
			return fmt.Errorf("%s does not match its kernel block-device identity", devicePath)
		}
		for name, expected := range map[string]uint64{
			"start": uint64(partition.StartingLBA),
			"size":  uint64(partition.EndingLBA - partition.StartingLBA + 1),
		} {
			data, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				return err
			}
			actual, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
			if err != nil {
				return err
			}
			if actual != expected {
				return fmt.Errorf("partition %d %s is %d sectors, GPT requires %d", partition.Index, name, actual, expected)
			}
		}
	}
	return nil
}

func (i *imageIntegrityProtector) integrityProtectImageOnDevice() error {
	if i.devPath == "" {
		log.Fatal("no device path")
	}

	i.enterScope()
	defer i.exitScope()

	if err := i.detectPartitions(); err != nil {
		return err
	}
	if err := i.syncIntegrityPartitionNodes(); err != nil {
		return err
	}

	if err := i.prepareRootPartition(); err != nil {
		return err
	}

	rootHash, verityFilePath, err := i.createIntegrityDataForRootPartition()
	if err != nil {
		return err
	}

	log.Infoln("dm-verity root hash for the root partition: ", rootHash)

	if err = i.createOrUpdateVerityPartition(verityFilePath); err != nil {
		return err
	}

	log.Infoln("generating manifest with integrity information for image on", i.devPath)

	partition := ImageManifestPartition{
		GptLabel: "cloudimg-rootfs",
		RootHash: rootHash,
		ReadOnly: true,
	}

	im := &ImageManifest{
		Partitions: []ImageManifestPartition{partition},
	}

	imJson, err := json.Marshal(im)
	if err != nil {
		return err
	}
	log.Infoln("manifest.json:", string(imJson))

	espPath, err := i.mountESP()
	if err != nil {
		return err
	}

	ukiRootPath := filepath.Join(espPath, "EFI/ubuntu")

	log.Infoln("creating manifest under", ukiRootPath)
	if err := os.WriteFile(filepath.Join(ukiRootPath, "manifest.json"), imJson, 0644); err != nil {
		return fmt.Errorf("cannot create manifest file: %w", err)
	}

	return nil
}

func (i *imageIntegrityProtector) integrityProtectImageFromFile() error {
	path, err := i.prepareWorkingImage(i.opts)
	switch {
	case err != nil:
		return fmt.Errorf("cannot prepare working image: %w", err)
	case path != "":
		// We aren't encrypting the source image
		i.addCleanup(func() error {
			if i.failed {
				return nil
			}
			if err := os.Rename(path, i.opts.Output); err != nil {
				return fmt.Errorf("cannot move working image to final path: %w", err)
			}
			return nil
		})
	default:
		// We are encrypting the source image
		path = i.opts.Positional.Input
	}

	if err := i.connectNbd(path); err != nil {
		return err
	}

	return i.integrityProtectImageOnDevice()
}

func (i *imageIntegrityProtector) setupWorkingDir() error {
	var baseDir string
	if i.opts.Output != "" {
		baseDir = filepath.Dir(i.opts.Output)
	}
	return i.encryptCloudImageBase.setupWorkingDir(baseDir)
}

func (i *imageIntegrityProtector) run(opts *integrityOptions) (err error) {
	i.opts = opts

	i.enterScope()
	defer i.exitScope()
	defer func() { i.failed = err != nil }()

	inputIsBlockDevice, err := fs.PathIsBlockDevice(opts.Positional.Input)
	if err != nil {
		return err
	}

	if opts.Output != "" && inputIsBlockDevice {
		return errors.New("cannot specify --output with a block device")
	}
	if inputIsBlockDevice {
		return errors.New("integrity-protect requires a disposable image file; block-device repartitioning is unsupported")
	}

	if err := i.setupWorkingDir(); err != nil {
		return err
	}

	if inputIsBlockDevice {
		// Source file is a block device
		i.devPath = opts.Positional.Input
		if i.isNbdDevice() {
			if err := i.checkNbdPreRequisites(); err != nil {
				return err
			}
		}

		return i.integrityProtectImageOnDevice()
	}

	// Source file is not a block device
	if err := i.checkNbdPreRequisites(); err != nil {
		return err
	}

	return i.integrityProtectImageFromFile()
}

func init() {
	if _, err := parser.AddCommand("integrity-protect", "Generate dm-verity data for the root fs partition and a configurationo manifest", "", &integrityOptions{}); err != nil {
		log.WithError(err).Panicln("cannot add verity command")
	}
}
