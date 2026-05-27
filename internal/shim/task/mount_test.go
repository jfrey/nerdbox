/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package task

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/nerdbox/internal/shim/sandbox"
	"github.com/containerd/nerdbox/internal/shim/task/bundle"
)

func applyOpts(opts []sandbox.Opt) sandbox.Options {
	var o sandbox.Options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func TestTransformMountsErofsBlockTransport(t *testing.T) {
	t.Setenv("NERDBOX_EROFS_TRANSPORT", "")
	da := newDiskAllocator()

	mounts, opts, err := transformMounts(context.Background(), "cid", []*types.Mount{
		{
			Type:    "erofs",
			Source:  "/tmp/root.erofs",
			Target:  "/",
			Options: []string{"loop", "ro"},
		},
	}, &da, nil)

	assert.NoError(t, err)
	if !assert.Len(t, mounts, 1) {
		return
	}
	assert.Equal(t, "/dev/vda", mounts[0].Source)
	assert.Equal(t, []string{"ro"}, mounts[0].Options)

	sbOpts := applyOpts(opts)
	assert.Equal(t, []sandbox.Disk{
		{BlockID: "disk-97-cid", MountPath: "/tmp/root.erofs", Flags: sandbox.DiskFlagReadonly},
	}, sbOpts.Disks)
	assert.Empty(t, sbOpts.PmemImages)
}

func TestTransformMountsErofsPmemTransport(t *testing.T) {
	t.Setenv("NERDBOX_EROFS_TRANSPORT", "pmem")
	da := newDiskAllocator()

	mounts, opts, err := transformMounts(context.Background(), "cid", []*types.Mount{
		{
			Type:    "erofs",
			Source:  "/tmp/root.erofs",
			Target:  "/",
			Options: []string{"loop", "ro"},
		},
	}, &da, nil)

	assert.NoError(t, err)
	if !assert.Len(t, mounts, 1) {
		return
	}
	assert.Equal(t, "/dev/pmem0", mounts[0].Source)
	assert.Equal(t, []string{"ro"}, mounts[0].Options)
	assert.Equal(t, 0, da.count())

	sbOpts := applyOpts(opts)
	assert.Empty(t, sbOpts.Disks)
	assert.Equal(t, []sandbox.PmemImage{
		{ImageID: "pmem-0-cid", MountPath: "/tmp/root.erofs", Readonly: true},
	}, sbOpts.PmemImages)
}

func TestTransformMountsErofsPmemTransportWithRequiredDmVerity(t *testing.T) {
	t.Setenv("NERDBOX_EROFS_TRANSPORT", "pmem")
	t.Setenv("PMEM_IMAGE_VERIFICATION", "required-dm-verity")
	image := filepath.Join(t.TempDir(), "root.erofs")
	assert.NoError(t, os.WriteFile(image, []byte("hello-pmem"), 0o600))
	assert.NoError(t, os.WriteFile(image+".verity.json", []byte(`{"version":1}`), 0o600))
	assert.NoError(t, os.WriteFile(image+".verity.sig", []byte("signed"), 0o600))
	verifyingKey := strings.Repeat("a1", 32)
	da := newDiskAllocator()

	mounts, opts, err := transformMounts(context.Background(), "cid", []*types.Mount{
		{
			Type:    "erofs",
			Source:  image,
			Target:  "/",
			Options: []string{"loop", "ro"},
		},
	}, &da, map[string]string{
		annotationErofsTransport:        "pmem",
		annotationPmemImageVerification: "required-dm-verity",
		annotationPmemImageVerifyingKey: verifyingKey,
	})

	assert.NoError(t, err)
	if !assert.Len(t, mounts, 1) {
		return
	}
	assert.Equal(t, "/dev/pmem0", mounts[0].Source)

	sbOpts := applyOpts(opts)
	if assert.Len(t, sbOpts.PmemImages, 1) {
		pmem := sbOpts.PmemImages[0]
		assert.Equal(t, "pmem-0-cid", pmem.ImageID)
		assert.Equal(t, image, pmem.MountPath)
		assert.True(t, pmem.Readonly)
		assert.Equal(t, image+".verity.json", pmem.VerityParamsPath)
		assert.Equal(t, image+".verity.sig", pmem.VeritySignaturePath)
		assert.Equal(t, verifyingKey, pmem.VerifyingKeyHex)
	}
}

func TestTransformMountsErofsPmemTransportRequiredDmVerityFailsClosed(t *testing.T) {
	t.Setenv("NERDBOX_EROFS_TRANSPORT", "pmem")
	t.Setenv("PMEM_IMAGE_VERIFICATION", "required-dm-verity")
	t.Setenv("PMEM_IMAGE_VERIFYING_KEY", strings.Repeat("a1", 32))
	da := newDiskAllocator()

	_, opts, err := transformMounts(context.Background(), "cid", []*types.Mount{
		{
			Type:   "erofs",
			Source: filepath.Join(t.TempDir(), "missing.erofs"),
			Target: "/",
		},
	}, &da, nil)

	assert.Error(t, err)
	assert.Empty(t, applyOpts(opts).PmemImages)
}

func TestTransformMountsErofsPmemRejectsMultiDevice(t *testing.T) {
	t.Setenv("NERDBOX_EROFS_TRANSPORT", "pmem")
	da := newDiskAllocator()

	_, opts, err := transformMounts(context.Background(), "cid", []*types.Mount{
		{
			Type:    "erofs",
			Source:  "/tmp/root.erofs",
			Target:  "/",
			Options: []string{"device=/tmp/layer.erofs"},
		},
	}, &da, nil)

	assert.Error(t, err)
	assert.Empty(t, applyOpts(opts).PmemImages)
	assert.Equal(t, 0, da.count())
}

func TestBlockMountsProvider(t *testing.T) {
	const id = "cid"

	testcases := []struct {
		name           string
		mounts         []specs.Mount
		wantDisks      []sandbox.Disk
		wantSpecMounts []specs.Mount
		wantVmMounts   []mount.Mount
	}{
		{
			name:           "no mounts",
			mounts:         nil,
			wantDisks:      nil,
			wantSpecMounts: nil,
			wantVmMounts:   nil,
		},
		{
			name: "no ext4 mounts",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantDisks: nil,
			wantSpecMounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantVmMounts: nil,
		},
		{
			name: "single ext4 mount read-write",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data"},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: 0},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
			},
		},
		{
			name: "single ext4 mount read-only",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data", Options: []string{"ro"}},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: sandbox.DiskFlagReadonly},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind", "ro"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda", Options: []string{"ro"}},
			},
		},
		{
			name: "multiple ext4 mounts",
			mounts: []specs.Mount{
				{Type: "ext4", Source: "/vol/vol1.img", Destination: "/data"},
				{Type: "ext4", Source: "/vol/vol2.img", Destination: "/logs", Options: []string{"ro"}},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/vol1.img", Flags: 0},
				{BlockID: "disk-98-cid", MountPath: "/vol/vol2.img", Flags: sandbox.DiskFlagReadonly},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
				{Type: "bind", Source: "/mnt/sdb", Destination: "/logs", Options: []string{"rbind", "ro"}},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
				{Type: "ext4", Source: "/dev/vdb", Target: "/mnt/sdb", Options: []string{"ro"}},
			},
		},
		{
			name: "mixed mount types",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "ext4", Source: "/vol/myvolume.img", Destination: "/data"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantDisks: []sandbox.Disk{
				{BlockID: "disk-97-cid", MountPath: "/vol/myvolume.img", Flags: 0},
			},
			wantSpecMounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "bind", Source: "/mnt/sda", Destination: "/data", Options: []string{"rbind"}},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantVmMounts: []mount.Mount{
				{Type: "ext4", Source: "/dev/vda", Target: "/mnt/sda"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Spec: specs.Spec{Mounts: tc.mounts},
			}

			da := newDiskAllocator()
			bm := &blockMounter{}
			err := bm.FromBundle(context.Background(), b, id, &da)
			assert.NoError(t, err)

			opts := applyOpts(bm.SandboxOpts())
			assert.Equal(t, tc.wantDisks, opts.Disks)
			assert.Equal(t, tc.wantSpecMounts, b.Spec.Mounts)
			assert.Equal(t, tc.wantVmMounts, bm.VmMounts())
		})
	}
}

func TestBindMountsProvider(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	testfile := filepath.Join(tmpDir, "testfile.txt")
	f, err := os.Create(testfile)
	assert.NoError(t, err)
	f.Close()

	// Create a test directory
	testdirData := filepath.Join(tmpDir, "testdir", "data")
	assert.NoError(t, os.MkdirAll(testdirData, 0755))
	testdirConfig := filepath.Join(tmpDir, "testdir", "config")
	assert.NoError(t, os.MkdirAll(testdirConfig, 0755))

	testcases := []struct {
		name            string
		mounts          []specs.Mount
		wantMounts      []bindMount
		wantSpecSources []string // expected sources in the OCI spec after transformation
		wantVmMounts    []mount.Mount
	}{
		{
			name:            "no mounts",
			mounts:          nil,
			wantMounts:      nil,
			wantSpecSources: nil,
			wantVmMounts:    nil,
		},
		{
			name: "no bind mounts",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantMounts:      nil,
			wantSpecSources: []string{"tmpfs", "proc"},
			wantVmMounts:    nil,
		},
		{
			name: "single bind mount",
			mounts: []specs.Mount{
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
			},
			wantSpecSources: []string{"/mnt/bind-8c5eaa445dd84f17"},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
			},
		},
		{
			name: "multiple bind mounts",
			mounts: []specs.Mount{
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
				{Type: "bind", Source: testdirConfig, Destination: "/container/config"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
				{
					tag:      "bind-529984c9ac58b7ec",
					hostSrc:  testdirConfig,
					vmTarget: "/mnt/bind-529984c9ac58b7ec",
				},
			},
			wantSpecSources: []string{
				"/mnt/bind-8c5eaa445dd84f17",
				"/mnt/bind-529984c9ac58b7ec",
			},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
				{Type: "virtiofs", Source: "bind-529984c9ac58b7ec", Target: "/mnt/bind-529984c9ac58b7ec"},
			},
		},
		{
			name: "mixed mount types",
			mounts: []specs.Mount{
				{Type: "tmpfs", Source: "tmpfs", Destination: "/tmp"},
				{Type: "bind", Source: testdirData, Destination: "/container/data"},
				{Type: "proc", Source: "proc", Destination: "/proc"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-8c5eaa445dd84f17",
					hostSrc:  testdirData,
					vmTarget: "/mnt/bind-8c5eaa445dd84f17",
				},
			},
			wantSpecSources: []string{
				"tmpfs",
				"/mnt/bind-8c5eaa445dd84f17",
				"proc",
			},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-8c5eaa445dd84f17", Target: "/mnt/bind-8c5eaa445dd84f17"},
			},
		},
		{
			name: "single file bind mount",
			mounts: []specs.Mount{
				{Type: "bind", Source: testfile, Destination: "/container/testfile"},
			},
			wantMounts: []bindMount{
				{
					tag:      "bind-6dace5108a719565",
					hostSrc:  tmpDir,
					vmTarget: "/mnt/bind-6dace5108a719565",
				},
			},
			wantSpecSources: []string{"/mnt/bind-6dace5108a719565/testfile.txt"},
			wantVmMounts: []mount.Mount{
				{Type: "virtiofs", Source: "bind-6dace5108a719565", Target: "/mnt/bind-6dace5108a719565"},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Spec: specs.Spec{
					Mounts: tc.mounts,
				},
			}

			bm := &bindMounter{}
			err := bm.FromBundle(context.Background(), b)
			assert.NoError(t, err)
			assert.Equal(t, tc.wantMounts, bm.mounts)

			// Verify that the spec sources were transformed
			for i, wantSource := range tc.wantSpecSources {
				assert.Equal(t, wantSource, b.Spec.Mounts[i].Source)
			}

			// Verify the VM mounts passed via MountAll RPC
			assert.Equal(t, tc.wantVmMounts, bm.VmMounts())
		})
	}
}
