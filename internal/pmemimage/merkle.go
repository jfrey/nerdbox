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
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const HashBlockSize = 4096

type MerkleCommitment struct {
	RootHex    string
	LeavesPath string
	ImageSize  int64
}

func PrepareMerkleCommitment(path string) (MerkleCommitment, error) {
	file, err := os.Open(path)
	if err != nil {
		return MerkleCommitment{}, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return MerkleCommitment{}, err
	}
	if stat.Size() == 0 {
		return MerkleCommitment{}, fmt.Errorf("pmem image %q is empty", path)
	}

	leaves, err := hashLeaves(file)
	if err != nil {
		return MerkleCommitment{}, err
	}
	root := merkleRoot(leaves)
	leavesPath, err := writeLeaves(path, root, leaves)
	if err != nil {
		return MerkleCommitment{}, err
	}

	return MerkleCommitment{
		RootHex:    hex.EncodeToString(root[:]),
		LeavesPath: leavesPath,
		ImageSize:  stat.Size(),
	}, nil
}

func hashLeaves(r io.Reader) ([][32]byte, error) {
	var leaves [][32]byte

	for {
		block := make([]byte, HashBlockSize)
		n, err := io.ReadFull(r, block)
		switch {
		case err == nil:
			leaves = append(leaves, sha256.Sum256(block))
		case err == io.EOF:
			if len(leaves) == 0 {
				return nil, fmt.Errorf("image produced no Merkle leaves")
			}
			return leaves, nil
		case err == io.ErrUnexpectedEOF:
			if n == 0 {
				return nil, fmt.Errorf("image produced an empty final Merkle block")
			}
			leaves = append(leaves, sha256.Sum256(block))
			return leaves, nil
		default:
			return nil, err
		}
	}
}

func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}

	current := append([][32]byte(nil), leaves...)
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := left
			if i+1 < len(current) {
				right = current[i+1]
			}
			var pair [64]byte
			copy(pair[:32], left[:])
			copy(pair[32:], right[:])
			next = append(next, sha256.Sum256(pair[:]))
		}
		current = next
	}
	return current[0]
}

func writeLeaves(imagePath string, root [32]byte, leaves [][32]byte) (string, error) {
	cacheDir, err := os.MkdirTemp("", "nerdbox-pmem-leaves-")
	if err != nil {
		return "", err
	}

	nameHash := sha256.Sum256([]byte(imagePath + "\x00" + hex.EncodeToString(root[:])))
	finalPath := filepath.Join(cacheDir, hex.EncodeToString(nameHash[:])+".leaves")
	tmp, err := os.CreateTemp(cacheDir, ".leaves-*.tmp")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	for _, leaf := range leaves {
		if _, err := tmp.Write(leaf[:]); err != nil {
			_ = tmp.Close()
			return "", err
		}
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	removeTmp = false
	return finalPath, nil
}
