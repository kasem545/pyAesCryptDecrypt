#!/usr/bin/env python3

import argparse
import gzip
import os
import sys
import time
import pyAesCrypt

MAX_PASS_LEN = 1024
DEFAULT_BUFFER_SIZE = 128 * 1024
ZIP_MAGIC = b'PK\x03\x04'

def open_wordlist(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")

def try_decrypt(aesfile, outfile, password, buffer_size):
    try:
        if os.path.exists(outfile):
            os.remove(outfile)
        pyAesCrypt.decryptFile(aesfile, outfile, password, buffer_size)
        return True
    except ValueError:
        return False
    except Exception as e:
        print(f"[!] Unexpected error with '{password[:40]}': {e}", file=sys.stderr)
        return False

def validate_decrypted_file(path):
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
            return header.startswith(ZIP_MAGIC)
    except Exception:
        return False

def brute_force(args):
    aesfile = args.aesfile
    wordlist = args.wordlist
    outfile = args.out
    buffer_size = args.buffer
    resume_line = args.resume

    if not os.path.exists(aesfile):
        sys.exit(f"[!] AES file not found: {aesfile}")
    if not os.path.exists(wordlist):
        sys.exit(f"[!] Wordlist not found: {wordlist}")

    print(f"\n[+] Starting brute-force...")
    print(f"    📂 Target     : {aesfile}")
    print(f"    📖 Wordlist   : {wordlist}")
    print(f"    💾 Output     : {outfile}")
    print(f"    🔁 Resume from: Line {resume_line}\n")

    found = None
    tried = 0
    start_time = time.time()

    try:
        with open_wordlist(wordlist) as f:
            if resume_line > 0:
                for _ in range(resume_line - 1):
                    f.readline()
                    tried += 1

            for line in f:
                tried += 1
                password = line.strip()

                if not password or len(password) > MAX_PASS_LEN:
                    continue

                if tried % 1000 == 0:
                    elapsed = time.time() - start_time
                    rate = tried / elapsed if elapsed > 0 else 0
                    print(f"[i] Tried: {tried:7} | Last: '{password[:30]:30}' | {rate:.1f} tries/s | Elapsed: {int(elapsed)}s")

                if try_decrypt(aesfile, outfile, password, buffer_size):
                    if validate_decrypted_file(outfile):
                        found = password
                        break
                    else:
                        os.remove(outfile)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user (Ctrl+C)")
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)

    if found:
        print(f"\n[✅] Password found: {found}")
        print(f"[✅] Output file   : {outfile}")
    else:
        print("\n[❌] Password not found in provided list.")

def main():
    parser = argparse.ArgumentParser(description="AES-256 brute-forcer using pyAesCrypt and a password list.")
    parser.add_argument("--aesfile", required=True, help="Input .aes encrypted file")
    parser.add_argument("--wordlist", required=True, help="Password list (.txt or .gz)")
    parser.add_argument("--out", default="decrypted.zip", help="Output file after decryption")
    parser.add_argument("--buffer", type=int, default=DEFAULT_BUFFER_SIZE, help="Buffer size for AES decryption (default: 128KB)")
    parser.add_argument("--resume", type=int, default=0, help="Resume from line number (1-indexed)")
    args = parser.parse_args()
    brute_force(args)

if __name__ == "__main__":
    main()
