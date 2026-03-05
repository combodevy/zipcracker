#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIP 密码破解工具
================
自动递进策略：内置字典 → 暴力穷举（纯数字 → 字母数字 → 全字符）
支持多进程并发加速，实时进度显示。

用法:
    python zip_cracker.py <zip文件>                           # 全自动模式
    python zip_cracker.py <zip文件> -d passwords.txt          # 使用外部字典
    python zip_cracker.py <zip文件> --mode bruteforce -c digits --max-len 6
    python zip_cracker.py <zip文件> --test                    # 自测模式
"""

import argparse
import binascii
import itertools
import multiprocessing
import os
import string
import struct
import sys
import time
import zipfile
import zlib
import tempfile
import shutil
from multiprocessing import Pool

# ============================================================
#  内置常用密码字典（~500条）
# ============================================================
BUILTIN_PASSWORDS = [
    # 纯数字 - 极常见
    "0", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678",
    "123456789", "1234567890", "0000", "00000", "000000", "0000000", "00000000",
    "1111", "11111", "111111", "1111111", "11111111", "2222", "22222", "222222",
    "3333", "33333", "333333", "4444", "44444", "444444", "5555", "55555", "555555",
    "6666", "66666", "666666", "7777", "77777", "777777", "8888", "88888", "888888",
    "9999", "99999", "999999", "1010", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "1314", "5201314", "520", "521", "1314520", "147258", "147258369",
    "159357", "123321", "654321", "7654321", "87654321", "987654321",
    "121212", "131313", "232323", "666888", "888666", "168168", "186186",
    "198964", "110110", "112112", "114114", "119119", "120120",
    "135790", "246810", "135792468", "1357924680",
    "101010", "202020", "010101", "998877", "112233", "332211",
    "aabbcc", "abcabc", "qazwsx", "zaqwsx",
    
    # 常见英文密码
    "password", "Password", "PASSWORD", "password1", "password123",
    "admin", "Admin", "admin123", "admin888", "administrator",
    "root", "toor", "root123", "root1234",
    "test", "test123", "test1234", "testing",
    "guest", "guest123", "default", "login",
    "master", "monkey", "dragon", "shadow", "sunshine",
    "trustno1", "iloveyou", "princess", "football", "baseball",
    "soccer", "hockey", "batman", "superman", "spider",
    "michael", "jennifer", "jordan", "robert", "daniel",
    "thomas", "charlie", "andrew", "joshua", "jessica",
    "abc123", "abc1234", "abcd1234", "abcdef", "abcdefg",
    "qwerty", "qwerty123", "qwertyuiop", "qwert", "asdfgh",
    "zxcvbn", "zxcvbnm", "asdfghjkl", "asdf1234",
    "letmein", "welcome", "welcome1", "hello", "hello123",
    "pass", "pass123", "pass1234", "passw0rd", "p@ssw0rd",
    "changeme", "secret", "access", "love", "god",
    "money", "power", "whatever", "computer", "internet",
    "server", "database", "system", "network",
    "file", "files", "backup", "temp", "data",
    "user", "user123", "member", "private", "public",
    
    # 键盘模式
    "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
    "1q2w3e", "1q2w3e4r", "1q2w3e4r5t", "1qaz2wsx", "1qaz2wsx3edc",
    "q1w2e3r4", "z1x2c3v4", "zaq12wsx", "qazwsxedc",
    "asd123", "zxc123", "qwe123", "qwe1234",
    "!@#$%", "!@#$%^", "!@#$%^&", "!@#$%^&*",
    "1!", "1!2@", "1!2@3#", "1!2@3#4$",
    
    # 中文拼音常见密码
    "woaini", "woaini1314", "woaini520", "woshishui",
    "nihao", "nihao123", "mima", "mima123",
    "aini", "aini1314", "meili", "kuaile",
    "zhongguo", "beijing", "shanghai", "shenzhen", "guangzhou",
    "jiayou", "dandan", "xiaoxiao", "mingming",
    "wangyue", "liuwei", "zhangwei", "wangfang",
    
    # 常见名字 + 数字
    "wang123", "li123", "zhang123", "chen123", "liu123",
    "yang123", "huang123", "zhao123", "wu123", "zhou123",
    
    # 日期格式
    "19900101", "19910101", "19920101", "19930101", "19940101",
    "19950101", "19960101", "19970101", "19980101", "19990101",
    "20000101", "20010101", "20020101", "20030101", "20040101",
    "20050101", "20060101", "20070101", "20080101", "20090101",
    "20100101", "900101", "910101", "920101", "930101",
    "940101", "950101", "960101", "970101", "980101", "990101",
    "000101", "010101", "0101", "0601", "1001",
    
    # 手机号前缀
    "13800138000", "138001380000",
    
    # 简单组合
    "aa", "aaa", "aaaa", "aaaaa", "aaaaaa",
    "ab", "abc", "abcd", "abcde",
    "a1", "a12", "a123", "a1234", "a12345", "a123456",
    "aa123", "aa1234", "aa123456",
    "qq123", "qq1234", "qq123456",
    "pp123", "pp1234",
    "xx123", "xx1234",
    "zz123", "zz1234",
    
    # 常见词汇
    "apple", "banana", "orange", "cherry",
    "cat", "dog", "fish", "bird", "tiger", "lion",
    "star", "moon", "sun", "sky", "ocean",
    "lucky", "happy", "cool", "good", "nice", "great", "best",
    "game", "play", "music", "movie", "photo", "video",
    "china", "usa", "japan", "korea",
    "fuck", "shit", "damn", "hell",
    "love123", "baby", "baby123", "honey", "angel", "devil",
    "king", "queen", "prince", "killer", "winner",
    "hacker", "crack", "hack", "virus",
    
    # 重复/简单模式
    "aabb", "abab", "aaaa1111", "1111aaaa",
    "aa11", "a1a1", "1a1a", "11aa",
    "abc111", "111abc", "aaa111", "111aaa",
    "aaa123", "123aaa", "zzz123", "123zzz",
    
    # 特殊字符组合
    "p@ss", "p@ssword", "p@55w0rd",
    "adm1n", "r00t", "us3r",
    "l0ve", "h@ck", "g0d",
    
    # 更多纯数字
    "159753", "357159", "258456", "147963",
    "741852", "963852", "852741", "369258",
    "102030", "908070", "998899", "889988",
    "123123", "456456", "789789", "321321",
    "111222", "222333", "333444", "444555",
    "555666", "666777", "777888", "888999",
    "111222333", "123456abc", "abc123456",
    "123abc", "abc321", "xyz123", "xyz789",
    
    # 常见弱密码补充
    "trustno1", "matrix", "freedom", "thunder", "ginger",
    "hammer", "silver", "golfer", "cookie", "coffee",
    "pepper", "summer", "winter", "spring", "autumn",
    "monday", "friday", "sunday",
    "january", "december",
    "diamond", "golden", "platinum",
    "pokemon", "naruto", "sasuke",
    "minecraft", "fortnite", "roblox",
    "google", "facebook", "twitter", "tiktok",
    "wechat", "alipay", "taobao", "baidu",
]


# ============================================================
#  字符集定义
# ============================================================
CHARSETS = {
    "digits":      string.digits,                                    # 0-9
    "lower":       string.ascii_lowercase,                           # a-z
    "upper":       string.ascii_uppercase,                           # A-Z
    "alpha":       string.ascii_letters,                             # a-zA-Z
    "alnum":       string.ascii_lowercase + string.digits,           # a-z0-9
    "alnumcase":   string.ascii_letters + string.digits,             # a-zA-Z0-9
    "all":         string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
}


# ============================================================
#  辅助：选择最小的文件用于密码测试（加快速度）
# ============================================================
def get_test_files(zip_path, use_pyzipper=False):
    """获取 ZIP 内用于密码测试的文件信息（优先选最小的非目录文件）"""
    try:
        if use_pyzipper:
            import pyzipper
            with pyzipper.AESZipFile(zip_path, 'r') as zf:
                infos = [i for i in zf.infolist() if i.file_size > 0]
        else:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                infos = [i for i in zf.infolist() if i.file_size > 0]
        
        if not infos:
            # 回退：返回所有文件名
            if use_pyzipper:
                import pyzipper
                with pyzipper.AESZipFile(zip_path, 'r') as zf:
                    return zf.namelist()[:2]
            else:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    return zf.namelist()[:2]
        
        # 按文件大小排序，选最小的（最多2个用于交叉验证）
        infos.sort(key=lambda x: x.file_size)
        return [i.filename for i in infos[:3]]
    except Exception:
        return None


# ============================================================
#  核心：尝试密码（带 CRC32 校验防误报）
# ============================================================
def try_password(zip_path, password, test_files=None):
    """
    尝试用给定密码解压 ZIP 文件
    通过读取文件内容并校验 CRC32 来确认密码正确性，防止误报
    """
    try:
        pwd_bytes = password.encode('utf-8')
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # 获取测试文件列表
            files_to_check = test_files
            if not files_to_check:
                infos = [i for i in zf.infolist() if i.file_size > 0]
                if infos:
                    infos.sort(key=lambda x: x.file_size)
                    files_to_check = [infos[0].filename]
                else:
                    files_to_check = zf.namelist()[:1]
            
            # 至少验证一个文件，读取内容并校验 CRC32
            for fname in files_to_check[:1]:
                info = zf.getinfo(fname)
                data = zf.read(fname, pwd=pwd_bytes)
                # 手动校验 CRC32
                actual_crc = binascii.crc32(data) & 0xFFFFFFFF
                expected_crc = info.CRC
                if actual_crc != expected_crc:
                    return None
            
            return password
    except (RuntimeError, zipfile.BadZipFile, zlib.error, KeyError,
            struct.error, EOFError, ValueError, OSError):
        return None
    except Exception:
        return None


def try_password_pyzipper(zip_path, password, test_files=None):
    """使用 pyzipper 尝试 AES 加密的 ZIP（AES 自带 HMAC 验证，更可靠）"""
    try:
        import pyzipper
        pwd_bytes = password.encode('utf-8')
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            files_to_check = test_files
            if not files_to_check:
                infos = [i for i in zf.infolist() if i.file_size > 0]
                if infos:
                    infos.sort(key=lambda x: x.file_size)
                    files_to_check = [infos[0].filename]
                else:
                    files_to_check = zf.namelist()[:1]
            
            for fname in files_to_check[:1]:
                data = zf.read(fname, pwd=pwd_bytes)
                # AES 加密有 HMAC 校验，如果读取成功数据就是正确的
                # 但额外做 CRC 校验更安全
                info = zf.getinfo(fname)
                if info.CRC:
                    actual_crc = binascii.crc32(data) & 0xFFFFFFFF
                    if actual_crc != info.CRC:
                        return None
            
            return password
    except Exception:
        return None


def verify_password(zip_path, password, use_pyzipper=False):
    """
    二次确认密码：读取 ZIP 内多个文件进行交叉验证
    用于在找到候选密码后做最终确认，消除误报
    """
    try:
        pwd_bytes = password.encode('utf-8')
        
        if use_pyzipper:
            import pyzipper
            zf_class = pyzipper.AESZipFile
        else:
            zf_class = zipfile.ZipFile
        
        with zf_class(zip_path, 'r') as zf:
            # 获取所有非空文件
            infos = [i for i in zf.infolist() if i.file_size > 0]
            if not infos:
                infos = [zf.getinfo(n) for n in zf.namelist()[:1]]
            
            # 按大小排序，验证最小的几个文件（最多3个）
            infos.sort(key=lambda x: x.file_size)
            check_infos = infos[:min(3, len(infos))]
            
            for info in check_infos:
                data = zf.read(info.filename, pwd=pwd_bytes)
                if info.CRC:
                    actual_crc = binascii.crc32(data) & 0xFFFFFFFF
                    if actual_crc != info.CRC:
                        return False
        
        return True
    except Exception:
        return False


def try_batch(args):
    """批量尝试一组密码（用于多进程）"""
    zip_path, passwords, use_pyzipper = args
    try_func = try_password_pyzipper if use_pyzipper else try_password
    for pwd in passwords:
        result = try_func(zip_path, pwd)
        if result:
            return result
    return None


# ============================================================
#  进度显示
# ============================================================
def format_time(seconds):
    """格式化时间"""
    if seconds < 0 or seconds > 365 * 24 * 3600:
        return "未知"
    if seconds < 60:
        return f"{seconds:.0f}秒"
    elif seconds < 3600:
        return f"{seconds/60:.1f}分钟"
    elif seconds < 86400:
        return f"{seconds/3600:.1f}小时"
    else:
        return f"{seconds/86400:.1f}天"


def format_number(n):
    """格式化大数字"""
    if n < 1000:
        return str(n)
    elif n < 1_000_000:
        return f"{n/1000:.1f}K"
    elif n < 1_000_000_000:
        return f"{n/1_000_000:.1f}M"
    else:
        return f"{n/1_000_000_000:.1f}B"


def print_progress(tried, total, start_time, current_pwd="", phase=""):
    """打印进度条"""
    elapsed = time.time() - start_time
    speed = tried / elapsed if elapsed > 0 else 0
    
    if total and total > 0:
        pct = min(tried / total * 100, 100)
        remaining = (total - tried) / speed if speed > 0 else 0
        bar_len = 30
        filled = int(bar_len * tried / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}% | "
            f"{format_number(tried)}/{format_number(total)} | "
            f"{format_number(speed)}/秒 | "
            f"剩余 {format_time(remaining)} | "
            f"{current_pwd[:20]}"
            f"          "
        )
    else:
        sys.stdout.write(
            f"\r  已尝试 {format_number(tried)} | "
            f"{format_number(speed)}/秒 | "
            f"耗时 {format_time(elapsed)} | "
            f"{current_pwd[:20]}"
            f"          "
        )
    sys.stdout.flush()


# ============================================================
#  字典攻击
# ============================================================
def dict_attack(zip_path, passwords, use_pyzipper=False, workers=None, label="字典攻击"):
    """字典攻击：逐一尝试密码列表"""
    if not passwords:
        return None
    
    total = len(passwords)
    if workers is None:
        workers = multiprocessing.cpu_count()
    
    print(f"\n{'='*60}")
    print(f"  ▶ {label}")
    print(f"    密码数量: {format_number(total)} | 进程数: {workers}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # 将密码列表分成批次
    batch_size = max(50, total // (workers * 10))
    batches = []
    for i in range(0, total, batch_size):
        batch = passwords[i:i + batch_size]
        batches.append((zip_path, batch, use_pyzipper))
    
    result = None
    tried = 0
    try:
        with Pool(processes=workers) as pool:
            async_results = pool.imap_unordered(try_batch, batches)
            for res in async_results:
                tried += batch_size
                tried = min(tried, total)
                print_progress(tried, total, start_time,
                               passwords[min(tried, total) - 1], label)
                
                if res is not None:
                    # 二次验证：用多个文件交叉校验，防止误报
                    print(f"\n  🔍 候选密码: {res}，正在二次验证...")
                    if verify_password(zip_path, res, use_pyzipper):
                        result = res
                        pool.terminate()
                        break
                    else:
                        print(f"  ⚠ 误报，继续搜索...")
    except KeyboardInterrupt:
        print("\n\n  ⚠ 用户中断")
        return None
    
    elapsed = time.time() - start_time
    print()
    
    if result:
        print(f"  ✅ 密码已确认！耗时 {format_time(elapsed)}")
    else:
        print(f"  ❌ 未找到，耗时 {format_time(elapsed)}")
    
    return result


# ============================================================
#  暴力破解生成器
# ============================================================
def bruteforce_generator(charset, min_len, max_len):
    """生成暴力破解的所有密码组合"""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)


def calc_total_combinations(charset_size, min_len, max_len):
    """计算总组合数"""
    total = 0
    for length in range(min_len, max_len + 1):
        total += charset_size ** length
    return total


def bruteforce_attack(zip_path, charset_name="digits", min_len=1, max_len=6,
                      use_pyzipper=False, workers=None):
    """暴力破解攻击"""
    charset = CHARSETS.get(charset_name, charset_name)
    total = calc_total_combinations(len(charset), min_len, max_len)
    
    if workers is None:
        workers = multiprocessing.cpu_count()
    
    print(f"\n{'='*60}")
    print(f"  ▶ 暴力破解 [{charset_name}]")
    print(f"    字符集: {charset[:30]}{'...' if len(charset) > 30 else ''} ({len(charset)}种字符)")
    print(f"    长度: {min_len}-{max_len}位 | 总组合: {format_number(total)} | 进程数: {workers}")
    print(f"{'='*60}")
    
    start_time = time.time()
    batch_size = max(500, min(50000, total // (workers * 20)))
    
    result = None
    tried = 0
    current_pwd_display = ""
    
    try:
        with Pool(processes=workers) as pool:
            gen = bruteforce_generator(charset, min_len, max_len)
            
            while True:
                # 收集一批密码
                batch = list(itertools.islice(gen, batch_size))
                if not batch:
                    break
                
                current_pwd_display = batch[0]
                
                # 分成子批次发给每个进程
                sub_batch_size = max(100, len(batch) // workers)
                sub_batches = []
                for i in range(0, len(batch), sub_batch_size):
                    sub = batch[i:i + sub_batch_size]
                    sub_batches.append((zip_path, sub, use_pyzipper))
                
                async_results = pool.map_async(try_batch, sub_batches)
                
                # 等待这批完成，同时更新进度
                while not async_results.ready():
                    print_progress(tried, total, start_time, current_pwd_display)
                    async_results.wait(0.5)
                
                # 检查结果
                for res in async_results.get():
                    if res is not None:
                        # 二次验证防误报
                        print(f"\n  🔍 候选密码: {res}，正在二次验证...")
                        if verify_password(zip_path, res, use_pyzipper):
                            result = res
                            pool.terminate()
                            break
                        else:
                            print(f"  ⚠ 误报，继续搜索...")
                
                tried += len(batch)
                
                if result:
                    break
                
                print_progress(tried, total, start_time, current_pwd_display)
    
    except KeyboardInterrupt:
        print("\n\n  ⚠ 用户中断")
        return None
    
    elapsed = time.time() - start_time
    print()
    
    if result:
        print(f"  ✅ 密码已确认！耗时 {format_time(elapsed)}")
    else:
        print(f"  ❌ 未找到，耗时 {format_time(elapsed)}")
    
    return result


# ============================================================
#  检测 ZIP 加密类型
# ============================================================
def detect_encryption(zip_path):
    """检测 ZIP 文件加密类型，返回 (is_encrypted, needs_pyzipper)"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # 加密标志位
                    # 检查是否为 AES 加密
                    # compression_type 99 = AES
                    if info.compress_type == 99:
                        return True, True
                    return True, False
            return False, False
    except zipfile.BadZipFile:
        print("  ❌ 错误: 文件不是有效的 ZIP 文件")
        sys.exit(1)


# ============================================================
#  自动模式
# ============================================================
def auto_mode(zip_path, dict_file=None, use_pyzipper=False, workers=None):
    """自动递进模式"""
    
    print("\n" + "╔" + "═"*58 + "╗")
    print("║" + "  🔓 ZIP 密码破解工具 - 自动递进模式".center(50) + "║")
    print("╚" + "═"*58 + "╝")
    print(f"\n  目标文件: {zip_path}")
    print(f"  文件大小: {os.path.getsize(zip_path) / 1024:.1f} KB")
    
    overall_start = time.time()
    
    # ---- 阶段1: 内置字典 ----
    result = dict_attack(zip_path, BUILTIN_PASSWORDS, use_pyzipper, workers,
                         "阶段1: 内置常用密码字典")
    if result:
        return result
    
    # ---- 阶段2: 外部字典 ----
    if dict_file and os.path.exists(dict_file):
        print(f"\n  📖 加载外部字典: {dict_file}")
        try:
            with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                ext_passwords = [line.strip() for line in f if line.strip()]
            print(f"  📖 已加载 {format_number(len(ext_passwords))} 条密码")
            result = dict_attack(zip_path, ext_passwords, use_pyzipper, workers,
                                 "阶段2: 外部字典攻击")
            if result:
                return result
        except Exception as e:
            print(f"  ⚠ 无法读取字典文件: {e}")
    
    # ---- 阶段3: 暴力破解 - 纯数字 1-8位 ----
    result = bruteforce_attack(zip_path, "digits", 1, 8, use_pyzipper, workers)
    if result:
        return result
    
    # ---- 阶段4: 暴力破解 - 小写字母+数字 1-5位 ----
    result = bruteforce_attack(zip_path, "alnum", 1, 5, use_pyzipper, workers)
    if result:
        return result
    
    # ---- 阶段5: 暴力破解 - 大小写+数字 1-4位 ----
    result = bruteforce_attack(zip_path, "alnumcase", 1, 4, use_pyzipper, workers)
    if result:
        return result
    
    # ---- 阶段6: 全字符集 1-4位 ----
    result = bruteforce_attack(zip_path, "all", 1, 4, use_pyzipper, workers)
    if result:
        return result
    
    # 所有阶段都没找到
    overall_elapsed = time.time() - overall_start
    print(f"\n{'='*60}")
    print(f"  😞 全部阶段执行完毕，未找到密码")
    print(f"  总耗时: {format_time(overall_elapsed)}")
    print(f"\n  💡 建议:")
    print(f"    1. 下载大型字典文件（如 rockyou.txt）重新尝试:")
    print(f"       python zip_cracker.py {zip_path} -d rockyou.txt")
    print(f"    2. 增大暴力破解范围:")
    print(f"       python zip_cracker.py {zip_path} --mode bruteforce -c alnum --max-len 8")
    print(f"    3. 尝试回忆密码的任何片段，可用掩码攻击缩小范围")
    print(f"{'='*60}")
    
    return None


# ============================================================
#  自测模式
# ============================================================
def run_self_test():
    """创建测试 ZIP 并验证工具功能"""
    print("\n  🧪 运行自测...")
    
    tmp_dir = tempfile.mkdtemp(prefix="zipcrack_test_")
    test_zip = os.path.join(tmp_dir, "test.zip")
    test_file = os.path.join(tmp_dir, "test.txt")
    
    try:
        # 创建测试文件
        with open(test_file, 'w') as f:
            f.write("Hello, this is a test file for ZIP cracker!")
        
        # 测试1: 字典内的密码
        print("\n  --- 测试1: 字典攻击（密码: 123456）---")
        import subprocess
        # 使用 Python 创建带密码的 ZIP（需要 pyzipper 或 pyminizip）
        # 回退方案：直接用 zipfile + 已知密码测试密码验证逻辑
        try:
            import pyzipper
            with pyzipper.AESZipFile(test_zip, 'w',
                                     compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b'123456')
                zf.write(test_file, 'test.txt')
            
            result = dict_attack(test_zip, BUILTIN_PASSWORDS, True, 2, "自测-字典攻击")
            if result == "123456":
                print("  ✅ 测试1 通过!")
            else:
                print(f"  ❌ 测试1 失败! 结果: {result}")
        except ImportError:
            # 没有 pyzipper，用标准 zipfile 创建 ZipCrypto 加密
            # 标准库不支持创建加密 ZIP，跳过或用命令行工具
            print("  ⚠ 需要 pyzipper 库来创建加密测试文件")
            print("    安装: pip install pyzipper")
            print("    或手动创建一个带密码的 ZIP 文件进行测试")
        
        # 测试2: 暴力破解
        test_zip2 = os.path.join(tmp_dir, "test2.zip")
        try:
            import pyzipper
            with pyzipper.AESZipFile(test_zip2, 'w',
                                     compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(b'357')
                zf.write(test_file, 'test.txt')
            
            print("\n  --- 测试2: 暴力破解（密码: 357, 纯数字3位）---")
            result = bruteforce_attack(test_zip2, "digits", 1, 3, True, 2)
            if result == "357":
                print("  ✅ 测试2 通过!")
            else:
                print(f"  ❌ 测试2 失败! 结果: {result}")
        except ImportError:
            pass
    
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    
    print("\n  🧪 自测完成\n")


# ============================================================
#  显示结果
# ============================================================
def show_result(password):
    """高亮显示找到的密码"""
    print()
    print("╔" + "═"*58 + "╗")
    print("║" + "  🎉 密码破解成功！".center(50) + "║")
    print("║" + " "*58 + "║")
    print("║" + f"  密码是:  {password}".center(50) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "═"*58 + "╝")
    print()


# ============================================================
#  交互模式（双击运行时使用）
# ============================================================
def interactive_mode():
    """当没有命令行参数时，进入交互模式"""
    print()
    print("╔" + "═"*58 + "╗")
    print("║" + "  🔓 ZIP 密码破解工具".center(52) + "║")
    print("╚" + "═"*58 + "╝")
    print()
    print("  使用方法:")
    print("    1. 直接将 ZIP 文件拖拽到本窗口，然后按回车")
    print("    2. 或手动输入 ZIP 文件的完整路径")
    print()
    
    zip_input = input("  请输入 ZIP 文件路径 (拖拽文件到此处): ").strip()
    
    if not zip_input:
        print("\n  ❌ 未输入文件路径")
        return
    
    # 去除拖拽文件时可能带的引号
    zip_input = zip_input.strip('"').strip("'")
    
    zip_path = os.path.abspath(zip_input)
    if not os.path.exists(zip_path):
        print(f"\n  ❌ 文件不存在: {zip_path}")
        return
    
    if not zip_path.lower().endswith('.zip'):
        print(f"\n  ⚠ 警告: 文件扩展名不是 .zip，将尝试作为 ZIP 文件处理...")
    
    # 检测加密
    is_encrypted, needs_pyzipper = detect_encryption(zip_path)
    
    if not is_encrypted:
        print("\n  ℹ️ 该 ZIP 文件没有加密，无需密码即可解压！")
        return
    
    if needs_pyzipper:
        try:
            import pyzipper
            print("  ℹ️ 检测到 AES 加密，使用 pyzipper 引擎")
        except ImportError:
            print("  ❌ 该 ZIP 使用 AES 加密，需要安装 pyzipper:")
            print("     pip install pyzipper")
            return
    else:
        print("  ℹ️ 检测到 ZipCrypto 加密")
    
    # 询问是否有外部字典
    print()
    dict_file = input("  如果有字典文件请输入路径，没有直接按回车跳过: ").strip()
    dict_file = dict_file.strip('"').strip("'") if dict_file else None
    if dict_file and not os.path.exists(dict_file):
        print(f"  ⚠ 字典文件不存在: {dict_file}，将跳过")
        dict_file = None
    
    workers = multiprocessing.cpu_count()
    
    # 启动全自动模式
    result = auto_mode(zip_path, dict_file, needs_pyzipper, workers)
    
    if result:
        show_result(result)
    else:
        print("\n  😞 未能找到密码")


# ============================================================
#  主函数
# ============================================================
def main():
    # 如果没有命令行参数（双击运行），进入交互模式
    if len(sys.argv) <= 1:
        interactive_mode()
        return
    
    # 处理特殊情况：第一个参数是 .zip 文件且没有其他参数标志
    # 允许直接拖拽文件到 exe/py 上运行
    if (len(sys.argv) == 2 and 
        not sys.argv[1].startswith('-') and 
        os.path.exists(sys.argv[1])):
        zip_path = os.path.abspath(sys.argv[1])
        is_encrypted, needs_pyzipper = detect_encryption(zip_path)
        
        if not is_encrypted:
            print("  ℹ️ 该 ZIP 文件没有加密，无需密码即可解压！")
            return
        
        if needs_pyzipper:
            try:
                import pyzipper
                print("  ℹ️ 检测到 AES 加密，使用 pyzipper 引擎")
            except ImportError:
                print("  ❌ 该 ZIP 使用 AES 加密，需要安装 pyzipper:")
                print("     pip install pyzipper")
                return
        else:
            print("  ℹ️ 检测到 ZipCrypto 加密")
        
        workers = multiprocessing.cpu_count()
        result = auto_mode(zip_path, None, needs_pyzipper, workers)
        if result:
            show_result(result)
        else:
            print("\n  😞 未能找到密码")
        return
    
    parser = argparse.ArgumentParser(
        description="ZIP 密码破解工具 - 自动递进策略",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s target.zip                              全自动模式
  %(prog)s target.zip -d passwords.txt              使用外部字典
  %(prog)s target.zip --mode bruteforce -c digits --max-len 8
  %(prog)s target.zip --mode dict -d rockyou.txt    纯字典模式
  %(prog)s --test                                   运行自测
        """
    )
    
    parser.add_argument("zipfile", nargs="?", help="要破解的 ZIP 文件路径")
    parser.add_argument("-d", "--dict", help="外部字典文件路径")
    parser.add_argument("--mode", choices=["auto", "dict", "bruteforce"],
                        default="auto", help="攻击模式 (默认: auto)")
    parser.add_argument("-c", "--charset",
                        choices=list(CHARSETS.keys()),
                        default="digits",
                        help="暴力破解字符集 (默认: digits)")
    parser.add_argument("--min-len", type=int, default=1,
                        help="最小密码长度 (默认: 1)")
    parser.add_argument("--max-len", type=int, default=6,
                        help="最大密码长度 (默认: 6)")
    parser.add_argument("-w", "--workers", type=int, default=None,
                        help=f"进程数 (默认: CPU核心数={multiprocessing.cpu_count()})")
    parser.add_argument("--test", action="store_true", help="运行自测")
    
    args = parser.parse_args()
    
    # 自测模式
    if args.test:
        run_self_test()
        return
    
    # 检查参数
    if not args.zipfile:
        parser.print_help()
        return
    
    zip_path = os.path.abspath(args.zipfile)
    if not os.path.exists(zip_path):
        print(f"  ❌ 错误: 文件不存在 - {zip_path}")
        return
    
    # 检测加密
    is_encrypted, needs_pyzipper = detect_encryption(zip_path)
    
    if not is_encrypted:
        print("  ℹ️ 该 ZIP 文件没有加密，无需密码即可解压！")
        return
    
    if needs_pyzipper:
        try:
            import pyzipper
            print("  ℹ️ 检测到 AES 加密，使用 pyzipper 引擎")
        except ImportError:
            print("  ❌ 该 ZIP 使用 AES 加密，需要安装 pyzipper:")
            print("     pip install pyzipper")
            return
    else:
        print("  ℹ️ 检测到 ZipCrypto 加密")
    
    workers = args.workers or multiprocessing.cpu_count()
    result = None
    
    # 执行攻击
    if args.mode == "auto":
        result = auto_mode(zip_path, args.dict, needs_pyzipper, workers)
    
    elif args.mode == "dict":
        passwords = list(BUILTIN_PASSWORDS)
        if args.dict and os.path.exists(args.dict):
            with open(args.dict, 'r', encoding='utf-8', errors='ignore') as f:
                passwords.extend(line.strip() for line in f if line.strip())
        result = dict_attack(zip_path, passwords, needs_pyzipper, workers)
    
    elif args.mode == "bruteforce":
        result = bruteforce_attack(zip_path, args.charset, args.min_len,
                                   args.max_len, needs_pyzipper, workers)
    
    # 显示结果
    if result:
        show_result(result)
    else:
        print("\n  😞 未能找到密码")
        if args.mode != "auto":
            print("  💡 提示: 试试全自动模式: python zip_cracker.py <file.zip>")


if __name__ == "__main__":
    # Windows 多进程必须在 __main__ 中
    multiprocessing.freeze_support()
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  ⚠ 用户中断，退出程序")
    except Exception as e:
        print(f"\n  ❌ 程序出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 防止窗口闪退：等待用户按回车再关闭
        print()
        input("  按回车键退出...")
