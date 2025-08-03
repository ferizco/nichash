package hashutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3"
)

type HashResult struct {
	FilePath string `json:"file_path"`
	HashType string `json:"hash_type"`
	Hash     string `json:"hash"`
}

func GetHasher(hashType string) (hash.Hash, error) {
	switch strings.ToLower(hashType) {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "md5":
		return md5.New(), nil
	case "sha3-256":
		return sha3.New256(), nil
	default:
		return nil, fmt.Errorf("unsupported hash type: %s", hashType)
	}
}

func GenerateFileHash(filePath, hashType string) (HashResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return HashResult{}, err
	}
	defer file.Close()

	hasher, err := GetHasher(hashType)
	if err != nil {
		return HashResult{}, err
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return HashResult{}, err
	}

	hashString := hex.EncodeToString(hasher.Sum(nil))
	return HashResult{
		FilePath: filePath,
		HashType: strings.ToUpper(hashType),
		Hash:     hashString,
	}, nil
}

func GenerateDirHash(dirPath, hashType string, onResult func(HashResult), onError func(string, error)) ([]HashResult, error) {
	var results []HashResult

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}

		result, err := GenerateFileHash(path, hashType)
		if err != nil {
			if onError != nil {
				onError(path, err)
			}
			return nil
		}

		if onResult != nil {
			onResult(result)
		}
		results = append(results, result)
		return nil
	})
	return results, err
}

func VerifyFileHash(filePath, hashType, expectedHash string) error {
	result, err := GenerateFileHash(filePath, hashType)
	if err != nil {
		return err
	}
	if !strings.EqualFold(result.Hash, expectedHash) {
		return fmt.Errorf("hash does not match. Expected: %s, Got: %s", expectedHash, result.Hash)
	}
	return nil
}

// CompareResults membandingkan hash hasil saat ini dengan referensi.
func CompareResults(actual, reference []HashResult) {
	referenceMap := make(map[string]HashResult)
	for _, ref := range reference {
		// Normalisasi path untuk jaga-jaga
		referenceMap[strings.TrimSpace(ref.FilePath)] = ref
	}

	matchCount := 0
	mismatchCount := 0
	notFoundCount := 0

	var mismatchFiles []string
	var notFoundFiles []string

	for _, a := range actual {
		ref, found := referenceMap[strings.TrimSpace(a.FilePath)]
		if !found {
			notFoundFiles = append(notFoundFiles, a.FilePath)
			notFoundCount++
			continue
		}

		// Bandingkan hash dengan ignore case
		if strings.EqualFold(a.Hash, ref.Hash) {
			matchCount++
		} else {
			mismatchFiles = append(mismatchFiles, a.FilePath)
			mismatchCount++
		}
	}

	fmt.Printf("Summary: %d match, %d mismatch, %d not found\n", matchCount, mismatchCount, notFoundCount)

	if mismatchCount > 0 {
		fmt.Println("\n❌ Mismatch:")
		for _, path := range mismatchFiles {
			fmt.Printf("- %s\n", path)
		}
	}

	if notFoundCount > 0 {
		fmt.Println("\n❌ Not found in reference:")
		for _, path := range notFoundFiles {
			fmt.Printf("- %s\n", path)
		}
	}
}
