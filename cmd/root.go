package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"nichash/hashutil"
	"nichash/internal"
	"nichash/output"
)

const version = "2.5.1"

func Execute() {
	fs := flag.NewFlagSet("nichash", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	filePath := fs.String("file", "", "Path of the file to generate hash")
	dirPath := fs.String("dir", "", "Path of the directory to hash files recursively")
	hashType := fs.String("hash", "sha256", "Hash type: sha256, sha512, sha1, md5, sha3-256 (default sha256)")
	outputFile := fs.String("o", "", "Output file (supports .txt, .json, .csv)")
	verifyHash := fs.String("verify", "", "Hash to verify against the file")
	showVersion := fs.Bool("version", false, "Show the version of the application")

	if len(os.Args) == 1 {
		internal.PrintUsage(fs, version)
		os.Exit(0)
	}

	for _, arg := range os.Args[1:] {
		if arg == "-help" || arg == "--help" {
			internal.PrintUsage(fs, version)
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'nichash -help' for usage.")
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("Nichash version: %s\n", version)
		return
	}

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

	if _, err := hashutil.GetHasher(*hashType); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *verifyHash != "" && *filePath == "" {
		fmt.Fprintln(os.Stderr, "Error: -verify must be used with -file")
		os.Exit(1)
	}

	if *filePath != "" && *verifyHash != "" {
		if err := hashutil.VerifyFileHash(*filePath, *hashType, *verifyHash); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		} else {
			fmt.Printf("File %s: hash matches!\n", *filePath)
		}
		return
	}

	var results []hashutil.HashResult
	hadError := false

	if *filePath != "" {
		result, err := hashutil.GenerateFileHash(*filePath, *hashType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			hadError = true
		} else {
			results = append(results, result)
		}
	}

	if *dirPath != "" {
		dirResults, err := hashutil.GenerateDirHash(*dirPath, *hashType)
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
		fmt.Fprintln(os.Stderr, "Error: No file or directory provided.")
		return
	}

	if *outputFile != "" {
		if err := output.SaveResultsToFile(results, *outputFile, outputFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	} else {
		for _, result := range results {
			fmt.Printf("%s hash of file %s: %s\n", result.HashType, result.FilePath, result.Hash)
		}
	}
}
