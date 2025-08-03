package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"nichash/hashutil"
	"os"
)

func SaveResultsToFile(results []hashutil.HashResult, outputFile, format string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	switch format {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)
	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()
		writer.Write([]string{"File Path", "Hash Type", "Hash"})
		for _, r := range results {
			writer.Write([]string{r.FilePath, r.HashType, r.Hash})
		}
	case "txt":
		for _, r := range results {
			fmt.Fprintf(file, "%s hash of file %s: %s\n", r.HashType, r.FilePath, r.Hash)
		}
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	return nil
}
