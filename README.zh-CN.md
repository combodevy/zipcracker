# ZIP Cracker Web 🚀

[English](README.md) | [简体中文](README.zh-CN.md)

一个现代化、高性能、且包含可视化 Web 界面（Frontend Dashboard）的 ZIP / 7z 压缩包密码破解工具。

基于 Python 和 Flask 构建，支持原生的多进程高并发破解能力。不论是简单的数字遍历，还是拥有复杂规则的**模糊密码查询（记忆碎片强化拼接）**，都可以通过简易直观的 UI 面板轻松操作！

## ✨ 核心特性 

- **🎨 现代化 Web UI 面板**：告别黑框命令行！实时观察破解进度（百分比、速度测试、已运行时间、剩余预估时间 ETA）。
- **⚡ 多进程极致性能**：底层通过 Python `multiprocessing` 加持，利用多核 CPU 最大化每秒爆破次数。并采用独立 Worker 进程机制，确保主界面永不卡顿。
- **🧩 记忆碎片（模糊密码）引擎**：
  - 如果你只记得密码中带有类似 `love` 的字眼，引擎将自动为你扩展出诸如 `love123`, `love1998`, `Love_888`, `LOVE@2024` 等几百种中国网民常用组合，优先排期测试！极大缩短爆破时间！
  - 支持专业级的掩码规则匹配（如 `?l?l?d?d` 代指任意两个小写字母配两个数字），实时在网页端计算候选数量。
- **🔒 智能算法防误报**：使用 ZIP 内部文件的 CRC32 码做二次密码拦截校验，杜绝传统破解工具常出现的“假密码（False Positive）”现象。
- **🔄 断点续传**：破解进程随时可停。关闭后重启，可顺着之前的进度继续往下跑，不再前功尽弃！
- **💼 全格式覆盖**：既支持普通无头压缩 `ZipCrypto`，也支持高强度 `AES-256` 以及深层加密的 `.7z` 压缩包算法。

## 🖥️ 界面预览

*(请在启动程序后通过浏览器访问 localhost:5000 体验)*

## 🛠️ 安装

需要 **Python 3.8+** 以上环境。

1. 克隆代码库：
   ```bash
   git clone https://github.com/combodevy/zipcracker.git
   cd zipcracker
   git checkout feature/web-ui-fuzzy-password
   ```

2. 安装依赖库：
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 运行

启动前端控制台服务器：
```bash
python app.py
```

终端会显示运行端口（默认 `http://127.0.0.1:5000`）。使用浏览器打开后，只需：
1. **拖拽上传** 你的目标 `.zip` 或 `.7z` 文件
2. 选择配置（如开启模糊密码，或选纯数字 6 位）
3. 调整你想占用的 **CPU 核心数**
4. 点击 **🚀 开始破解**！

## 🐣 小白安装教程

如果你完全没有编程经验，请按照下面的步骤操作：

### 1. 安装 Python (这是运行工具的发动机)
- 前往 [Python 官网](https://www.python.org/downloads/windows/) 下载最新版。
- **关键一步**：安装时一定要勾选底部的 **"Add Python to PATH"**（将 Python 添加到路径），否则后面会报错！
- 点击 "Install Now" 直到完成。
<img width="836" height="528" alt="image" src="https://github.com/user-attachments/assets/868c3886-7ac0-4485-a365-4f145808d2d6" />

### 2. 下载本工具
- **如果你会用 Git**：在你要存放的文件夹打开终端，运行：
  ```bash
  git clone https://github.com/combodevy/zipcracker.git
  cd zipcracker
  ```
- **如果你不会用 Git**：点击本页面顶部的绿色按钮 **"Code"**，选择 **"Download ZIP"**。下载后解压到电脑里的文件夹即可。

### 3. 安装依赖软件
- 在工具所在的文件夹空白处，按住键盘 **Shift 键** 同时 **点鼠标右键**，选择 “在此处打开 PowerShell 窗口” 或 “在终端中打开”。
- 输入这行命令并按回车：
  ```bash
  pip install -r requirements.txt
  ```

### 4. 运行工具
- 在同一个黑框框里，输入并按回车：
  ```bash
  python app.py
  ```
- 当你看到屏幕提示 `Running on http://127.0.0.1:5000` 时，说明成功了！
- 打开你的浏览器，在地址栏输入 `http://127.0.0.1:5000` 即可看到操作界面。

---

## ❓ 常见问题与解决 (救急手册)

### Q: 克隆时报错 `RPC failed; curl 28 Recv failure: Connection was reset`？
**A**: 这是网络连接不稳定。解决方法：
1. **增加缓存**：输入 `git config --global http.postBuffer 524288000`
2. **只克隆最新版**：输入 `git clone --depth 1 https://github.com/combodevy/zipcracker.git`

### Q: 提示 `python` 或 `pip` 不是内部或外部命令？
**A**: 说明你安装 Python 时忘记勾选 "Add to PATH" 了。
- **解决**：卸载 Python 重新安装，并务必勾选那个选项；或者手动在系统环境变量里添加 Python 路径。

### Q: 依赖安装很慢或超时？
**A**: 试试国内加速镜像：
```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### Q: 界面打不开（5000 端口被占用）？
**A**: 可能是你之前运行过一次没关掉。关闭所有黑框框（终端）重新打开试试。

---

## 📄 授权与声明
本项目仅供网络安全学习、技术研究及合法找回本人遗失密码之用。严禁用于任何非法入侵破坏他人隐私及财物的活动。使用者产生之一切法律后果由其自行承担。
