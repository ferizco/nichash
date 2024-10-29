#!/bin/bash

# Cek apakah file binary sudah didownload
if [ ! -f nichash ]; then
  echo "Binary file not found! Please download the go-hash-cli binary first."
  exit 1
fi

# Pindahkan binary ke /usr/local/bin
sudo mv nichash /usr/local/bin/

# Berikan izin eksekusi
sudo chmod +x /usr/local/bin/nichash

echo "Installed Successfully"
