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

	"golang.org/x/crypto/sha3"
)

const version = "2.5.0"

type HashResult struct {
	FilePath string `json:"file_path"`
	HashType string `json:"hash_type"`
	Hash     string `json:"hash"`
}

func main() {
	fs := flag.NewFlagSet("nichash", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // menutup output default Go

	// Define flags
	filePath := fs.String("file", "", "Path of the file to generate hash")
	dirPath := fs.String("dir", "", "Path of the directory to hash files recursively")
	hashType := fs.String("hash", "sha256", "Hash type: sha256, sha512, sha1, md5, sha3-256 (default sha256)")
	outputFile := fs.String("o", "", " Output file (supports .txt, .json, .csv)")
	verifyHash := fs.String("verify", "", "Hash to verify against the file")
	showVersion := fs.Bool("version", false, "Show the version of the application")

	if len(os.Args) == 1 {
		printUsage(fs)
		os.Exit(0)
	}

	// Manual help handler
	for _, arg := range os.Args[1:] {
		if arg == "-help" || arg == "--help" {
			printUsage(fs)
			os.Exit(0)
		}
	}

	// Parse flags
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		os.Exit(1)
	}

	// Show version
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
			fmt.Fprintln(os.Stderr, "Error: Output format not supported. Please use .txt, .json, or .csv.")
			return
		}
	}

	// Validasi awal hash type sebelum proses file/directory
	if _, err := getHasher(*hashType); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		os.Exit(1)
	}

	// -verify hanya untuk -file
	if *verifyHash != "" && *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: The -verify flag can only be used with -file, not with -dir.")
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		os.Exit(1)
	}

	// Verify hash
	if *filePath != "" && *verifyHash != "" {
		if err := verifyFileHash(*filePath, *hashType, *verifyHash); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			fmt.Printf("File %s: hash matches!\n", *filePath)
		}
		return
	}

	var results []HashResult
	hadError := false

	if *filePath != "" {
		result, err := generateFileHash(*filePath, *hashType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			hadError = true
		} else {
			results = append(results, result)
		}
	}

	if *dirPath != "" {
		dirResults, err := generateDirHash(*dirPath, *hashType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			hadError = true
		} else {
			results = append(results, dirResults...)
		}
	}

	if hadError {
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		return
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Please provide a file path (-file) or directory path (-dir).")
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		return
	}

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

// ======================
// Fungsi Pendukung
// ======================

const banner = `
 _   _ _      _               _     
| \ | (_)    | |             | |    
|  \| |_  ___| |__   __ _ ___| |__  
| . ` + "`" + ` | |/ __| '_ \ / _` + "`" + ` / __| '_ \ 
| |\  | | (__| | | | (_| \__ \ | | |
|_| \_|_|\___|_| |_|\__,_|___/_| |_|
`

func printUsage(fs *flag.FlagSet) {
	fmt.Print(banner)
	fmt.Fprintf(os.Stderr, `Secure, Fast, and Flexible Hash Generator
Version: %s
Author: Ferizco

Usage:
  nichash [options]

Options:
`, version)
	fs.SetOutput(os.Stderr)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, `
Examples:
  nichash -file test.txt -hash sha256 -o hash.txt
  nichash -dir ./myfolder -hash sha512 -o hash.json
  nichash -file test.txt -verify <HASH>`)
}

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

func generateDirHash(dirPath, hashType string) ([]HashResult, error) {
	var results []HashResult
	var hadError bool

	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, fmt.Errorf("directory not found: %s", dirPath)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dirPath)
	}

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("cannot access path %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}

		result, err := generateFileHash(path, hashType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing file %s: %v\n", path, err)
			hadError = true
		} else {
			results = append(results, result)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	if len(results) == 0 && hadError {
		return nil, fmt.Errorf("no files were successfully processed")
	}

	return results, nil
}

func verifyFileHash(filePath, hashType, expectedHash string) error {
	result, err := generateFileHash(filePath, hashType)
	if err != nil {
		return err
	}
	if !strings.EqualFold(result.Hash, expectedHash) {
		return fmt.Errorf("hash does not match. Expected: %s, Result: %s", expectedHash, result.Hash)
	}
	return nil
}

func getHasher(hashType string) (hash.Hash, error) {
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
			return fmt.Errorf("failed to write JSON file: %w", err)
		}
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()
		writer.Write([]string{"File Path", "Hash Type", "Hash"})
		for _, result := range results {
			writer.Write([]string{result.FilePath, result.HashType, result.Hash})
		}
	case "txt":
		for _, result := range results {
			fmt.Fprintf(file, "%s hash of file %s: %s\n", result.HashType, result.FilePath, result.Hash)
		}
	default:
		return fmt.Errorf("unrecognized format: %s", format)
	}
	return nil
}
