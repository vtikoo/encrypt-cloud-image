package main

import (
	"encoding/json"
	"testing"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/encrypt-cloud-image/internal/gpt"
)

func TestIntegrityManifestReadOnlyConsumer(t *testing.T) {
	manifest := ImageManifest{
		Partitions: []ImageManifestPartition{{
			GptLabel: "cloudimg-rootfs",
			RootHash: "0123456789abcdef",
			ReadOnly: true,
		}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var consumer struct {
		Partitions []struct {
			Label    string `json:"label"`
			RootHash string `json:"root_hash"`
			ReadOnly bool   `json:"read_only"`
		} `json:"partitions"`
	}
	if err := json.Unmarshal(data, &consumer); err != nil {
		t.Fatal(err)
	}
	if len(consumer.Partitions) != 1 || !consumer.Partitions[0].ReadOnly ||
		consumer.Partitions[0].Label != "cloudimg-rootfs" ||
		consumer.Partitions[0].RootHash != "0123456789abcdef" {
		t.Fatalf("manifest does not select one verified read-only lower: %s", data)
	}
	var raw map[string][]map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["partitions"][0]["overlay"]; ok {
		t.Fatalf("manifest contains the incompatible overlay field: %s", data)
	}
}

func TestVerityPartitionFitsUsesInclusiveByteSize(t *testing.T) {
	partition := &gpt.PartitionEntry{PartitionEntry: &efi.PartitionEntry{
		StartingLBA: 100,
		EndingLBA:   107,
	}}
	for _, test := range []struct {
		size uint64
		fits bool
	}{{4095, true}, {4096, true}, {4097, false}} {
		if got := verityPartitionFits(partition, test.size); got != test.fits {
			t.Errorf("size %d: got %t, want %t", test.size, got, test.fits)
		}
	}
}
