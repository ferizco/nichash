package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nichash/hashutil"
	"nichash/output"
)

// Helper: membuat file di direktori sementara
func createTestFile(t *testing.T, name, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, name)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("gagal membuat file: %v", err)
	}
	return filePath
}

func createTestFileAt(t *testing.T, dir, name, content string) string {
	t.Helper()
	filePath := filepath.Join(dir, name)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("gagal membuat file di direktori: %v", err)
	}
	return filePath
}

func TestGenerateFileHash(t *testing.T) {
	file := createTestFile(t, "test.txt", "hello world")
	result, err := hashutil.GenerateFileHash(file, "sha256")
	if err != nil {
		t.Fatalf("generateFileHash gagal: %v", err)
	}
	if result.Hash == "" {
		t.Error("hash tidak boleh kosong")
	}
	if result.FilePath != file {
		t.Errorf("path tidak sesuai: dapat %s, ingin %s", result.FilePath, file)
	}
}

func TestGenerateDirHash(t *testing.T) {
	dir := t.TempDir()
	createTestFileAt(t, dir, "a.txt", "data A")
	createTestFileAt(t, dir, "b.txt", "data B")

	var collected []hashutil.HashResult

	results, err := hashutil.GenerateDirHash(dir, "sha1",
		func(res hashutil.HashResult) {
			collected = append(collected, res)
		},
		func(path string, err error) {
			t.Errorf("hash gagal untuk file %s: %v", path, err)
		},
	)

	if err != nil {
		t.Fatalf("generateDirHash gagal: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("seharusnya ada 2 hash, dapat %d", len(results))
	}
	if len(collected) != 2 {
		t.Errorf("callback onResult hanya dipanggil %d kali, seharusnya 2", len(collected))
	}
}

func TestVerifyFileHash(t *testing.T) {
	file := createTestFile(t, "verify.txt", "verifikasi data")

	result, err := hashutil.GenerateFileHash(file, "sha256")
	if err != nil {
		t.Fatal(err)
	}

	err = hashutil.VerifyFileHash(file, "sha256", result.Hash)
	if err != nil {
		t.Errorf("hash seharusnya cocok, tapi gagal: %v", err)
	}

	err = hashutil.VerifyFileHash(file, "sha256", "1234567890abcdef")
	if err == nil {
		t.Error("seharusnya gagal jika hash tidak cocok")
	}
}

func TestGetHasher(t *testing.T) {
	valid := []string{"sha256", "sha512", "sha1", "md5", "sha3-256"}
	for _, algo := range valid {
		_, err := hashutil.GetHasher(algo)
		if err != nil {
			t.Errorf("seharusnya mendukung %s, tapi error: %v", algo, err)
		}
	}

	_, err := hashutil.GetHasher("unsupported")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Error("seharusnya error untuk hash tidak didukung")
	}
}

// Dummy data untuk testing output
var dummyResults = []hashutil.HashResult{
	{FilePath: "/tmp/test1.txt", HashType: "SHA256", Hash: "abc123"},
	{FilePath: "/tmp/test2.txt", HashType: "SHA256", Hash: "def456"},
}

func TestSaveResultsToFile_JSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")

	err := output.SaveResultsToFile(dummyResults, path, "json")
	if err != nil {
		t.Fatalf("gagal menyimpan file JSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var parsed []hashutil.HashResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("file JSON tidak valid: %v", err)
	}

	if len(parsed) != len(dummyResults) {
		t.Errorf("jumlah hasil tidak cocok, dapat %d, ingin %d", len(parsed), len(dummyResults))
	}
}

func TestSaveResultsToFile_CSV(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.csv")

	err := output.SaveResultsToFile(dummyResults, path, "csv")
	if err != nil {
		t.Fatalf("gagal menyimpan file CSV: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(dummyResults)+1 {
		t.Errorf("jumlah baris CSV tidak sesuai: %d", len(lines))
	}
}

func TestSaveResultsToFile_TXT(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.txt")

	err := output.SaveResultsToFile(dummyResults, path, "txt")
	if err != nil {
		t.Fatalf("gagal menyimpan file TXT: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, result := range dummyResults {
		expected := fmt.Sprintf("%s hash of file %s: %s", result.HashType, result.FilePath, result.Hash)
		if !strings.Contains(string(data), expected) {
			t.Errorf("konten TXT tidak mengandung baris: %s", expected)
		}
	}
}

func TestVerifyAllFromJSON(t *testing.T) {
	tmp := t.TempDir()
	createTestFileAt(t, tmp, "a.txt", "data A")
	createTestFileAt(t, tmp, "b.txt", "data B")

	results, _ := hashutil.GenerateDirHash(tmp, "sha256", nil, nil)

	// Simpan ke JSON
	refPath := filepath.Join(tmp, "hash.json")
	saveResultsForVerifyTest(t, results, refPath, "json")

	reference, err := hashutil.LoadHashReference(refPath)
	if err != nil {
		t.Fatalf("Gagal load JSON: %v", err)
	}

	// Tidak error saat dibandingkan
	hashutil.CompareResults(results, reference)
}

func TestVerifyAllFromCSV(t *testing.T) {
	tmp := t.TempDir()
	createTestFileAt(t, tmp, "a.txt", "data A")
	createTestFileAt(t, tmp, "b.txt", "data B")

	results, _ := hashutil.GenerateDirHash(tmp, "sha256", nil, nil)

	refPath := filepath.Join(tmp, "hash.csv")
	saveResultsForVerifyTest(t, results, refPath, "csv")

	reference, err := hashutil.LoadHashReference(refPath)
	if err != nil {
		t.Fatalf("Gagal load CSV: %v", err)
	}

	hashutil.CompareResults(results, reference)
}

func TestVerifyAllFromTXT(t *testing.T) {
	tmp := t.TempDir()
	createTestFileAt(t, tmp, "a.txt", "data A")
	createTestFileAt(t, tmp, "b.txt", "data B")

	results, _ := hashutil.GenerateDirHash(tmp, "sha256", nil, nil)

	refPath := filepath.Join(tmp, "hash.txt")
	saveResultsForVerifyTest(t, results, refPath, "txt")

	reference, err := hashutil.LoadHashReference(refPath)
	if err != nil {
		t.Fatalf("Gagal load TXT: %v", err)
	}

	hashutil.CompareResults(results, reference)
}

func saveResultsForVerifyTest(t *testing.T, results []hashutil.HashResult, path, format string) {
	t.Helper()
	switch format {
	case "json":
		data, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(path, data, 0644)
	case "csv":
		f, _ := os.Create(path)
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"File Path", "Hash Type", "Hash"})
		for _, r := range results {
			w.Write([]string{r.FilePath, r.HashType, r.Hash})
		}
		w.Flush()
	case "txt":
		var lines []string
		for _, r := range results {
			lines = append(lines, fmt.Sprintf("%s hash of file %s: %s", r.HashType, r.FilePath, r.Hash))
		}
		_ = os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
	}
}
