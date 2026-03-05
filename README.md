# ZIP Cracker Web 🚀

[English](README.md) | [简体中文](README.zh-CN.md)

A modern, high-performance ZIP / 7z archive password cracking tool with a visual Web interface (Frontend Dashboard).

Built on Python and Flask, it supports native multi-process high-concurrency cracking. Whether it's a simple digit traversal or a complex rule-based **Fuzzy Password query (fragment-based reinforcement)**, you can easily operate it through a simple and intuitive UI panel!

## ✨ Key Features

- **🎨 Modern Web UI Dashboard**: Say goodbye to the black command line! Real-time observation of cracking progress (percentage, speed test, elapsed time, estimated time remaining ETA).
- **⚡ Multi-process Extreme Performance**: Powered by Python `multiprocessing`, utilizing multi-core CPUs to maximize cracks per second. It uses an independent Worker process mechanism to ensure the main UI never lags.
- **🧩 Memory Fragments (Fuzzy Password) Engine**:
  - If you only remember parts of the password like `love`, the engine will automatically expand into hundreds of common combinations such as `love123`, `love1998`, `Love_888`, `LOVE@2024`, and test them with priority! This significantly reduces cracking time!
  - Supports professional-grade mask rule matching (e.g., `?l?l?d?d` for any two lowercase letters and two digits), with real-time candidate count calculation on the web side.
- **🔒 Intelligent Anti-False Positive**: Uses the CRC32 code of internal files for secondary password verification, eliminating "False Positives" common in traditional cracking tools.
- **🔄 Breakpoint Contination**: The cracking process can be stopped at any time. After closing and restarting, it can continue from the previous progress, no longer starting from scratch!
- **💼 Full Format Coverage**: Supports both standard Legacy `ZipCrypto`, high-strength `AES-256`, and deep-encrypted `.7z` archive algorithms.

## 🖥️ UI Preview

*(Please access localhost:5000 via browser after starting the program to experience it)*

## 🛠️ Installation

Requires **Python 3.8+** environment.

1. Clone the repository:
   ```bash
   git clone https://github.com/combodevy/zipcracker.git
   cd zipcracker
   git checkout feature/web-ui-fuzzy-password
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Running

Start the frontend console server:
```bash
python app.py
```

The terminal will display the running port (default `http://127.0.0.1:5000`). Once opened in your browser, simply:
1. **Drag and drop** your target `.zip` or `.7z` file.
2. Select configuration (e.g., enable fuzzy password, or select 6-digit pure numbers).
3. Adjust the number of **CPU cores** you want to use.
4. Click **🚀 Start Cracking**!

## 🐣 Super Beginner Tutorial 

If you have zero programming experience, please follow these steps:

### 1. Install Python (The Engine)
- Go to [Python Official Website](https://www.python.org/downloads/windows/) and download the latest version.
- **CRITICAL STEP**: During installation, make sure to check the box **"Add Python to PATH"** at the bottom. Otherwise, it won't work!
- Click "Install Now" until finished.

### 2. Download This Tool
- **If you use Git**: Open your terminal in the target folder and run:
  ```bash
  git clone https://github.com/combodevy/zipcracker.git
  cd zipcracker
  ```
- **If you don't use Git**: Click the green **"Code"** button at the top of this page and select **"Download ZIP"**. Extract the downloaded file to a folder on your computer.

### 3. Install Required Components
- In your tool's folder, hold the **Shift key** and **Right-click** on empty space, then select "Open PowerShell window here" or "Open in Terminal".
- Type this command and press Enter:
  ```bash
  pip install -r requirements.txt
  ```

### 4. Run the Tool
- In the same terminal window, type this and press Enter:
  ```bash
  python app.py
  ```
- When you see `Running on http://127.0.0.1:5000`, success!
- Open your browser and type `http://127.0.0.1:5000` in the address bar to start.

---

## ❓ Troubleshooting (Emergency Manual)

### Q: Git error `RPC failed; curl 28 Recv failure: Connection was reset`?
**A**: This is due to unstable network connectivity. 
1. **Increase Buffer**: Type `git config --global http.postBuffer 524288000`
2. **Shallow Clone**: Type `git clone --depth 1 https://github.com/combodevy/zipcracker.git`

### Q: `python` or `pip` is not recognized as an internal or external command?
**A**: You likely missed the "Add to PATH" checkbox during Python installation.
- **Solution**: Re-install Python and ensure that option is checked.

### Q: Installation is slow or timed out?
**A**: Use a faster mirror (for users in specific regions):
```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: Web interface won't open (Port 5000 occupied)?
**A**: You might have another instance running. Close all terminal windows and try again.

---

## 📄 License & Disclaimer
This project is for network security learning, technical research, and legal retrieval of one's own lost passwords only. It is strictly forbidden for any illegal intrusion or destruction of others' privacy and property. All legal consequences generated by the user shall be borne by themselves.
