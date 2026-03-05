# 🔓 ZIP Password Cracker

[English](README.md) | [简体中文](README.zh-CN.md)

A powerful ZIP archive password cracking tool supporting multiple attack strategies, multi-process acceleration, and AES encryption.

## ✨ Features

- **Automatic Progressive Cracking** — Built-in dictionary → Pure digits brute-force → Alphanumeric → All characters, automatically upgrades step by step.
- **500+ Built-in Common Password Dictionary** — Covers common digits, English words, Pinyin, keyboard patterns, etc.
- **External Dictionary Support** — Can load large dictionary files like `rockyou.txt`.
- **Multi-process Concurrency** — Automatically utilizes all CPU cores for acceleration.
- **CRC32 Check + Secondary Verification** — Effectively prevents false positives.
- **Dual Encryption Support** — Supports both ZipCrypto and AES encryption.
- **Real-time Progress Display** — Progress bar, speed, estimated time remaining.
- **Interactive Mode** — Ready to run with a double-click, supports drag-and-drop.

## 📦 Requirements

- **Python 3.6+**
- (Optional) `pyzipper` — Only needed for cracking **AES encrypted** ZIP files:
  ```bash
  pip install pyzipper
  ```
  > If `pip` is unavailable, use: `python -m pip install pyzipper`

## 🚀 Usage

### Method 1: Double-click to Run (Recommended for beginners)

Double-click `zip_cracker.py` and follow the prompts:

1. **Drag and drop** the ZIP file into the window and press Enter.
2. If you have an external dictionary, enter its path; otherwise, press Enter to skip.
3. Wait for automatic cracking.

### Method 2: Drag-and-drop File

Drag the ZIP file directly onto the `zip_cracker.py` file icon.

### Method 3: Command Line

```bash
# Automatic mode (recommended)
python zip_cracker.py target_file.zip

# Using an external dictionary
python zip_cracker.py target_file.zip -d dictionary_file.txt

# Brute-force - pure digits, max 6 bits
python zip_cracker.py target_file.zip --mode bruteforce -c digits --max-len 6

# Brute-force - alphanumeric, max 5 bits
python zip_cracker.py target_file.zip --mode bruteforce -c alnum --max-len 5

# Self-test mode
python zip_cracker.py target_file.zip --test
```

## 📊 Automatic Cracking Strategy

Automatic mode follows the sequence below and stops when the password is found:

| Stage | Strategy | Range |
|:---:|------|------|
| 1 | Built-in Dictionary | ~500 common passwords |
| 2 | External Dictionary (if provided) | Custom |
| 3 | Brute-force - Pure Digits | 1~8 digits |
| 4 | Brute-force - Lower Alphanumeric | 1~5 chars |
| 5 | Brute-force - Case-sensitive Alphanumeric | 1~4 chars |
| 6 | Brute-force - Full Character Set | 1~4 chars |

## 🔤 Available Character Sets

| Name | Content | Count |
|------|------|:------:|
| `digits` | `0-9` | 10 |
| `lower` | `a-z` | 26 |
| `upper` | `A-Z` | 26 |
| `alpha` | `a-zA-Z` | 52 |
| `alnum` | `a-z0-9` | 36 |
| `alnumcase` | `a-zA-Z0-9` | 62 |
| `all` | Letters + Digits + Special Symbols | 90+ |

## 💡 Tips

- The tool will **automatically detect** the encryption type (ZipCrypto / AES); no manual configuration is required.
- Press **Ctrl+C** to interrupt at any time.
- If the password is not found in automatic mode, it is recommended to:
  1. Download a large dictionary (like [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)) and use it with the `-d` parameter.
  2. Increase the brute-force range: `--max-len 8` or more.
  3. Try to recall the character types in the password and select the corresponding charset to narrow the search space.

## ⚠️ Disclaimer

This tool is for educational and research purposes only, intended for recovering one's own forgotten ZIP passwords. Do not use it for any illegal purposes. All consequences arising from the use of this tool are the responsibility of the user.

## 📄 License

MIT License
