package internal

import (
	"flag"
	"fmt"
	"os"
)

const banner = `
 _   _ _      _               _     
| \ | (_)    | |             | |    
|  \| |_  ___| |__   __ _ ___| |__  
| . ` + "`" + ` | |/ __| '_ \ / _` + "`" + ` / __| '_ \ 
| |\  | | (__| | | | (_| \__ \ | | |
|_| \_|_|\___|_| |_|\__,_|___/_| |_|
`

func PrintUsage(fs *flag.FlagSet, version string) {
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
