package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3" // Install dengan: go get golang.org/x/crypto/sha3
)

const version = "2.4.0"

// HashResult represents the hash result for a file
type HashResult struct {
	FilePath string `json:"file_path"`
	HashType string `json:"hash_type"`
	Hash     string `json:"hash"`
}

func main() {
	// Define flags
	filePath := flag.String("file", "", "Path of the file to generate hash")
	dirPath := flag.String("dir", "", "Path of the directory to hash files recursively")
	hashType := flag.String("h", "sha256", "Hash type: sha256, sha512, sha1, md5, sha3-256")
	outputFile := flag.String("o", "", "Output file (supports .txt, .json, .csv)")
	verifyHash := flag.String("verify", "", "Hash to verify against the file")
	showVersion := flag.Bool("version", false, "Show the version of the application")

	// Redefine default Usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Nichash - A flexible file hash generator
Version: %s
Author: Ferizco

Usage:
  nichash [options]

Options:
`, version)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  nichash -file test.txt -h sha256 -o hash.txt    Generate SHA-256 hash for test.txt and save to hash.txt
  nichash -file test.txt -h sha256 -verify e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  nichash -dir ./myfolder -h sha512 -o hash.json Generate SHA-512 hash for all files in ./myfolder recursively and save to hash.json
  nichash -version                               Display the application version`)
	}

	// Parse flags
	flag.Parse()

	// Handle -version flag
	if *showVersion {
		fmt.Printf("Nichash version: %s\n", version)
		return
	}

	// Check output format
	outputFormat := "txt"
	if *outputFile != "" {
		ext := strings.ToLower(filepath.Ext(*outputFile))
		if ext == ".json" || ext == ".csv" || ext == ".txt" {
			outputFormat = strings.TrimPrefix(ext, ".")
		} else {
			fmt.Fprintln(os.Stderr, "Error: Unsupported output file format. Use .txt, .json, or .csv.")
			return
		}
	}

	// Handle -verify flag
	if *filePath != "" && *verifyHash != "" {
		if err := verifyFileHash(*filePath, *hashType, *verifyHash); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			fmt.Printf("File %s: Hash matches!\n", *filePath)
		}
		return
	}

	// Prepare to store results
	var results []HashResult

	// Handle -file flag
	if *filePath != "" {
		if result, err := generateFileHash(*filePath, *hashType); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			results = append(results, result)
		}
	}

	// Handle -dir flag
	if *dirPath != "" {
		if dirResults, err := generateDirHash(*dirPath, *hashType); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			results = append(results, dirResults...)
		}
	}

	// If neither -file nor -dir is provided
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Please provide a file path (-file) or directory path (-dir).")
		flag.Usage()
		return
	}

	// Output results to file or stdout
	if *outputFile != "" {
		if err := saveResultsToFile(results, *outputFile, outputFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	} else {
		for _, result := range results {
			fmt.Printf("%s hash of file %s: %s\n", result.HashType, result.FilePath, result.Hash)
		}
	}
}

// generateFileHash calculates and returns the hash of a single file
func generateFileHash(filePath, hashType string) (HashResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return HashResult{}, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher, err := getHasher(hashType)
	if err != nil {
		return HashResult{}, err
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return HashResult{}, fmt.Errorf("failed to read file: %w", err)
	}

	hashString := hex.EncodeToString(hasher.Sum(nil))
	return HashResult{FilePath: filePath, HashType: strings.ToUpper(hashType), Hash: hashString}, nil
}

// generateDirHash calculates and returns the hash of all files in a directory recursively
func generateDirHash(dirPath, hashType string) ([]HashResult, error) {
	var results []HashResult

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %s: %w", path, err)
		}

		if info.IsDir() {
			return nil
		}

		result, err := generateFileHash(path, hashType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing file %s: %v\n", path, err)
		} else {
			results = append(results, result)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", dirPath, err)
	}

	return results, nil
}

// verifyFileHash verifies the hash of a single file against the expected hash
func verifyFileHash(filePath, hashType, expectedHash string) error {
	result, err := generateFileHash(filePath, hashType)
	if err != nil {
		return err
	}

	if !strings.EqualFold(result.Hash, expectedHash) {
		return fmt.Errorf("hash does not match. Expected: %s, Found: %s", expectedHash, result.Hash)
	}

	return nil
}

// getHasher returns the hash function based on the hash type
func getHasher(hashType string) (hash.Hash, error) {
	hashType = strings.ToLower(hashType)
	switch hashType {
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

// saveResultsToFile saves the hash results to a file in the specified format
func saveResultsToFile(results []HashResult, outputFile, format string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch format {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(results); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()
		// Write header
		if err := writer.Write([]string{"File Path", "Hash Type", "Hash"}); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
		// Write records
		for _, result := range results {
			if err := writer.Write([]string{result.FilePath, result.HashType, result.Hash}); err != nil {
				return fmt.Errorf("failed to write CSV record: %w", err)
			}
		}
	case "txt":
		for _, result := range results {
			if _, err := fmt.Fprintf(file, "%s hash of file %s: %s\n", result.HashType, result.FilePath, result.Hash); err != nil {
				return fmt.Errorf("failed to write TXT output: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	return nil
}
