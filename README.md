# 🔓 ZIP Password Cracker

一款强大的 ZIP 压缩包密码破解工具，支持多种攻击策略、多进程加速和 AES 加密。（Antigravity+Claude）

## ✨ 特性

- **全自动递进破解** — 内置字典 → 纯数字暴力 → 字母数字 → 全字符，自动逐步升级
- **内置 500+ 常用密码字典** — 覆盖常见数字、英文、拼音、键盘模式等
- **支持外部字典** — 可加载 `rockyou.txt` 等大型字典文件
- **多进程并发** — 自动利用所有 CPU 核心加速破解
- **CRC32 校验 + 二次验证** — 有效防止误报
- **双加密支持** — 同时支持 ZipCrypto 和 AES 加密
- **实时进度显示** — 进度条、速度、预计剩余时间
- **交互模式** — 双击即可运行，支持拖拽文件

## 📦 环境要求

- **Python 3.6+**
- （可选）`pyzipper` — 仅在破解 **AES 加密** 的 ZIP 时需要：
  ```bash
  pip install pyzipper
  ```
  > 如果 `pip` 不可用，请使用：`python -m pip install pyzipper`

## 🚀 使用方法

### 方式一：双击运行（推荐小白用户）

直接双击 `zip_cracker.py`，按照提示操作：

1. 将 ZIP 文件**拖拽**到窗口中，按回车
2. 如果有字典文件输入路径，没有直接按回车跳过
3. 等待自动破解

### 方式二：拖拽文件

将 ZIP 文件直接拖拽到 `zip_cracker.py` 文件图标上。

### 方式三：命令行

```bash
# 全自动模式（推荐）
python zip_cracker.py 目标文件.zip

# 使用外部字典
python zip_cracker.py 目标文件.zip -d 字典文件.txt

# 暴力破解 - 纯数字，最长6位
python zip_cracker.py 目标文件.zip --mode bruteforce -c digits --max-len 6

# 暴力破解 - 小写字母+数字，最长5位
python zip_cracker.py 目标文件.zip --mode bruteforce -c alnum --max-len 5

# 自测模式
python zip_cracker.py 目标文件.zip --test
```

## 📊 自动破解策略

全自动模式按以下顺序递进，找到密码即停止：

| 阶段 | 策略 | 范围 |
|:---:|------|------|
| 1 | 内置常用密码字典 | ~500 个常见密码 |
| 2 | 外部字典（如已提供） | 自定义 |
| 3 | 暴力破解 - 纯数字 | 1~8 位 |
| 4 | 暴力破解 - 小写字母+数字 | 1~5 位 |
| 5 | 暴力破解 - 大小写+数字 | 1~4 位 |
| 6 | 暴力破解 - 全字符集 | 1~4 位 |

## 🔤 可用字符集

| 名称 | 内容 | 字符数 |
|------|------|:------:|
| `digits` | `0-9` | 10 |
| `lower` | `a-z` | 26 |
| `upper` | `A-Z` | 26 |
| `alpha` | `a-zA-Z` | 52 |
| `alnum` | `a-z0-9` | 36 |
| `alnumcase` | `a-zA-Z0-9` | 62 |
| `all` | 字母 + 数字 + 特殊符号 | 90+ |

## 💡 提示

- 工具会**自动检测**加密类型（ZipCrypto / AES），无需手动配置
- 运行过程中按 **Ctrl+C** 可随时中断
- 如果全自动未找到密码，建议：
  1. 下载大型字典（如 [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)）配合 `-d` 参数使用
  2. 增大暴力破解范围：`--max-len 8` 或更大
  3. 尝试回忆密码中包含的字符类型，选择对应字符集缩小范围

## ⚠️ 免责声明

本工具仅供学习和研究使用，用于恢复自己忘记的 ZIP 密码。请勿将其用于任何非法用途。使用本工具所产生的一切后果由使用者自行承担。

## 📄 License

MIT License
