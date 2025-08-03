package hashutil

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func LoadHashReference(path string) ([]HashResult, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return loadJSON(path)
	case ".csv":
		return loadCSV(path)
	case ".txt":
		return loadTXT(path)
	default:
		return nil, fmt.Errorf("format referensi tidak didukung: %s", ext)
	}
}

func loadJSON(path string) ([]HashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []HashResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func loadCSV(path string) ([]HashResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(rows) < 2 {
		return nil, errors.New("file CSV tidak berisi data")
	}

	var results []HashResult
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 3 {
			continue
		}
		results = append(results, HashResult{
			FilePath: strings.TrimSpace(row[0]),
			HashType: strings.TrimSpace(row[1]),
			Hash:     strings.TrimSpace(row[2]),
		})
	}
	return results, nil
}

func loadTXT(path string) ([]HashResult, error) {
	// Format:
	// SHA256 hash of file ./path/to/file: hashvalue
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var results []HashResult

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " hash of file ", 2)
		if len(parts) != 2 {
			continue
		}
		hashType := strings.TrimSpace(parts[0])
		rest := strings.SplitN(parts[1], ": ", 2)
		if len(rest) != 2 {
			continue
		}
		filePath := strings.TrimSpace(rest[0])
		hashVal := strings.TrimSpace(rest[1])

		results = append(results, HashResult{
			FilePath: filePath,
			HashType: hashType,
			Hash:     hashVal,
		})
	}
	return results, nil
}
