package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// Helper: membuat file langsung di direktori yang diberikan
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
	result, err := generateFileHash(file, "sha256")
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

	results, err := generateDirHash(dir, "sha1")
	if err != nil {
		t.Fatalf("generateDirHash gagal: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("seharusnya ada 2 hash, dapat %d", len(results))
	}
}

func TestVerifyFileHash(t *testing.T) {
	file := createTestFile(t, "verify.txt", "verifikasi data")

	// Hitung hash untuk dibandingkan
	result, err := generateFileHash(file, "sha256")
	if err != nil {
		t.Fatal(err)
	}

	// Harus cocok
	err = verifyFileHash(file, "sha256", result.Hash)
	if err != nil {
		t.Errorf("hash seharusnya cocok, tapi gagal: %v", err)
	}

	// Harus gagal jika hash salah
	err = verifyFileHash(file, "sha256", "1234567890abcdef")
	if err == nil {
		t.Error("seharusnya gagal jika hash tidak cocok")
	}
}

func TestGetHasher(t *testing.T) {
	valid := []string{"sha256", "sha512", "sha1", "md5", "sha3-256"}
	for _, algo := range valid {
		_, err := getHasher(algo)
		if err != nil {
			t.Errorf("seharusnya mendukung %s, tapi error: %v", algo, err)
		}
	}

	// Tes yang tidak didukung
	_, err := getHasher("unsupported")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Error("seharusnya error untuk hash tidak didukung")
	}
}

// Data dummy untuk tes output
var dummyResults = []HashResult{
	{FilePath: "/tmp/test1.txt", HashType: "SHA256", Hash: "abc123"},
	{FilePath: "/tmp/test2.txt", HashType: "SHA256", Hash: "def456"},
}

func TestSaveResultsToFile_JSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.json")

	err := saveResultsToFile(dummyResults, path, "json")
	if err != nil {
		t.Fatalf("gagal menyimpan file JSON: %v", err)
	}

	// Verifikasi konten JSON valid
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var parsed []HashResult
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

	err := saveResultsToFile(dummyResults, path, "csv")
	if err != nil {
		t.Fatalf("gagal menyimpan file CSV: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(dummyResults)+1 { // +1 untuk header
		t.Errorf("jumlah baris CSV tidak sesuai: %d", len(lines))
	}
}

func TestSaveResultsToFile_TXT(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "output.txt")

	err := saveResultsToFile(dummyResults, path, "txt")
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
