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

package pmemimage

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrepareMerkleCommitmentZeroPadsFinalBlock(t *testing.T) {
	image := t.TempDir() + "/rootfs.erofs"
	require.NoError(t, os.WriteFile(image, []byte("abc"), 0o600))

	got, err := PrepareMerkleCommitment(image)
	require.NoError(t, err)
	require.Equal(t, int64(3), got.ImageSize)
	require.FileExists(t, got.LeavesPath)

	block := make([]byte, HashBlockSize)
	copy(block, "abc")
	leaf := sha256.Sum256(block)
	require.Equal(t, hex.EncodeToString(leaf[:]), got.RootHex)

	leaves, err := os.ReadFile(got.LeavesPath)
	require.NoError(t, err)
	require.Equal(t, leaf[:], leaves)
}

func TestPrepareMerkleCommitmentRejectsEmptyImage(t *testing.T) {
	image := t.TempDir() + "/empty.erofs"
	require.NoError(t, os.WriteFile(image, nil, 0o600))

	_, err := PrepareMerkleCommitment(image)
	require.Error(t, err)
}
