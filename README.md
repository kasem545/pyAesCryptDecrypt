# 🔐 pyAesDecrypt

A simple and efficient AES-256 brute-force tool using `pyAesCrypt` and a wordlist (supports `.gz`).

## Features

- Supports plaintext and `.gz` compressed wordlists
- Auto-resume from any line
- Detects successful decryption via file magic (ZIP format)
- Clean CLI with progress display

## 🔧 Usage

```bash
pip install -r requirements
```

```bash
python3 pyAesCryptDecrypt.py --aesfile secret.aes --wordlist rockyou.txt
