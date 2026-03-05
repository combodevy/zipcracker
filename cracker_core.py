#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIP 密码破解 - 核心模块
========================
提供字典攻击、暴力破解、CRC32 校验、断点续破等核心功能。
供 CLI (zip_cracker.py) 和 Web UI (app.py) 共同调用。
"""

import binascii
import itertools
import json
import multiprocessing
import os
import re
import string
import struct
import sys
import time
import zipfile
import zlib
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
    "digits":      string.digits,
    "lower":       string.ascii_lowercase,
    "upper":       string.ascii_uppercase,
    "alpha":       string.ascii_letters,
    "alnum":       string.ascii_lowercase + string.digits,
    "alnumcase":   string.ascii_letters + string.digits,
    "all":         string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
}

CHARSET_LABELS = {
    "digits":    "纯数字 (0-9)",
    "lower":     "小写字母 (a-z)",
    "upper":     "大写字母 (A-Z)",
    "alpha":     "全部字母 (a-zA-Z)",
    "alnum":     "小写字母+数字 (a-z0-9)",
    "alnumcase": "大小写+数字 (a-zA-Z0-9)",
    "all":       "全字符集 (字母+数字+符号)",
}


# ============================================================
#  辅助函数
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
            if use_pyzipper:
                import pyzipper
                with pyzipper.AESZipFile(zip_path, 'r') as zf:
                    return zf.namelist()[:2]
            else:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    return zf.namelist()[:2]

        infos.sort(key=lambda x: x.file_size)
        return [i.filename for i in infos[:3]]
    except Exception:
        return None


def detect_archive_type(file_path):
    """通过文件头魔数识别压缩包格式"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        if header[:2] == b'PK':
            return 'zip'
        if header[:6] == b'7z\xbc\xaf\x27\x1c':
            return '7z'
        if header[:4] == b'Rar!':
            return 'rar'
    except Exception:
        pass
    # fallback 到扩展名
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.7z':
        return '7z'
    if ext == '.rar':
        return 'rar'
    return 'zip'


def detect_encryption(file_path):
    """检测压缩包加密类型，支持 ZIP 和 7z"""
    archive_type = detect_archive_type(file_path)

    if archive_type == '7z':
        return _detect_encryption_7z(file_path)
    else:
        return _detect_encryption_zip(file_path)


def _detect_encryption_7z(file_path):
    """检测 7z 文件加密"""
    result = {
        "is_encrypted": False,
        "needs_pyzipper": False,
        "archive_type": "7z",
        "encryption_type": "none",
        "file_count": 0,
        "total_size": 0,
        "file_list": [],
    }
    try:
        import py7zr  # type: ignore
        # 先尝试无密码打开
        try:
            with py7zr.SevenZipFile(file_path, 'r') as zf:
                for entry in zf.list():
                    result["file_count"] += 1
                    size = entry.uncompressed if hasattr(entry, 'uncompressed') else 0
                    result["total_size"] += size
                    result["file_list"].append({
                        "name": entry.filename,
                        "size": size,
                        "compressed_size": entry.compressed if hasattr(entry, 'compressed') else 0,
                    })
                # 检查是否加密
                if zf.password is not None:
                    result["is_encrypted"] = True
                    result["encryption_type"] = "7z-AES-256"
        except py7zr.exceptions.PasswordRequired:
            result["is_encrypted"] = True
            result["encryption_type"] = "7z-AES-256"
            # 加密时尝试获取文件列表（可能头部信息可读）
            try:
                with py7zr.SevenZipFile(file_path, 'r', password='__probe__') as zf:
                    for entry in zf.list():
                        result["file_count"] += 1
                        size = entry.uncompressed if hasattr(entry, 'uncompressed') else 0
                        result["total_size"] += size
                        result["file_list"].append({
                            "name": entry.filename,
                            "size": size,
                            "compressed_size": entry.compressed if hasattr(entry, 'compressed') else 0,
                        })
            except Exception:
                pass
    except ImportError:
        result["encryption_type"] = "7z-need-py7zr"
    except Exception:
        result["encryption_type"] = "invalid"
    return result


def _detect_encryption_zip(file_path):
    """检测 ZIP 文件加密"""
    result = {
        "is_encrypted": False,
        "needs_pyzipper": False,
        "archive_type": "zip",
        "encryption_type": "none",
        "file_count": 0,
        "total_size": 0,
        "file_list": [],
    }
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            for info in zf.infolist():
                result["file_count"] += 1
                result["total_size"] += info.file_size
                result["file_list"].append({
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                })
                if info.flag_bits & 0x1:
                    result["is_encrypted"] = True
                    if info.compress_type == 99:
                        result["needs_pyzipper"] = True
                        result["encryption_type"] = "AES"
                    else:
                        result["encryption_type"] = "ZipCrypto"
    except zipfile.BadZipFile:
        result["encryption_type"] = "invalid"
    return result


# ============================================================
#  核心密码尝试函数（带 CRC32 校验防误报）
# ============================================================
def try_password(zip_path, password, test_files=None):
    """尝试用给定密码解压 ZIP 文件（ZipCrypto）"""
    try:
        pwd_bytes = password.encode('utf-8')
        with zipfile.ZipFile(zip_path, 'r') as zf:
            files_to_check = test_files
            if not files_to_check:
                infos = [i for i in zf.infolist() if i.file_size > 0]
                if infos:
                    infos.sort(key=lambda x: x.file_size)
                    files_to_check = [infos[0].filename]
                else:
                    files_to_check = zf.namelist()[:1]

            for fname in files_to_check[:1]:
                info = zf.getinfo(fname)
                data = zf.read(fname, pwd=pwd_bytes)
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
    """使用 pyzipper 尝试 AES 加密的 ZIP"""
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
                info = zf.getinfo(fname)
                if info.CRC:
                    actual_crc = binascii.crc32(data) & 0xFFFFFFFF
                    if actual_crc != info.CRC:
                        return None

            return password
    except Exception:
        return None


def verify_password(file_path, password, use_pyzipper=False, archive_type='zip'):
    """二次确认密码：支持 ZIP 和 7z"""
    if archive_type == '7z':
        return _verify_password_7z(file_path, password)
    try:
        pwd_bytes = password.encode('utf-8')
        if use_pyzipper:
            import pyzipper
            zf_class = pyzipper.AESZipFile
        else:
            zf_class = zipfile.ZipFile

        with zf_class(file_path, 'r') as zf:
            infos = [i for i in zf.infolist() if i.file_size > 0]
            if not infos:
                infos = [zf.getinfo(n) for n in zf.namelist()[:1]]

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


def _verify_password_7z(file_path, password):
    """二次确认 7z 密码"""
    try:
        import py7zr  # type: ignore
        with py7zr.SevenZipFile(file_path, 'r', password=password) as zf:
            # 尝试解压所有文件，7z 的 AES 自带 HMAC 校验
            zf.readall()
        return True
    except Exception:
        return False


def try_batch(args):
    """批量尝试一组密码（多进程）——自动路由 ZIP/7z"""
    # args 格式: (path, passwords, use_pyzipper, test_files, archive_type)
    # 兼容旧格式: (path, passwords, use_pyzipper, test_files)
    if len(args) >= 5:
        file_path, passwords, use_pyzipper, test_files, archive_type = args[:5]
    else:
        file_path, passwords, use_pyzipper, test_files = args[:4]
        archive_type = 'zip'

    if archive_type == '7z':
        return _try_batch_7z(file_path, passwords)
    else:
        return _try_batch_zip(file_path, passwords, use_pyzipper, test_files)


def _try_batch_7z(file_path, passwords):
    """批量尝试 7z 密码"""
    try:
        import py7zr  # type: ignore
        for pwd in passwords:
            try:
                with py7zr.SevenZipFile(file_path, 'r', password=pwd) as zf:
                    # 7z AES 自带 HMAC 校验，读取成功即密码正确
                    zf.readall()
                return pwd
            except Exception:
                continue
    except Exception:
        pass
    return None


def _try_batch_zip(file_path, passwords, use_pyzipper, test_files):
    """批量尝试 ZIP 密码——每批只打开一次"""
    try:
        if use_pyzipper:
            import pyzipper
            zf = pyzipper.AESZipFile(file_path, 'r')
        else:
            zf = zipfile.ZipFile(file_path, 'r')

        fnames = test_files
        if not fnames:
            infos = [i for i in zf.infolist() if i.file_size > 0]
            if infos:
                infos.sort(key=lambda x: x.file_size)
                fnames = [infos[0].filename]
            else:
                fnames = zf.namelist()[:1]

        fname = fnames[0] if fnames else None
        if not fname:
            zf.close()
            return None

        info = zf.getinfo(fname)
        expected_crc = info.CRC

        for pwd in passwords:
            try:
                pwd_bytes = pwd.encode('utf-8')
                data = zf.read(fname, pwd=pwd_bytes)
                if expected_crc:
                    actual_crc = binascii.crc32(data) & 0xFFFFFFFF
                    if actual_crc == expected_crc:
                        zf.close()
                        return pwd
                else:
                    zf.close()
                    return pwd
            except Exception:
                continue

        zf.close()
    except Exception:
        pass
    return None


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


# ============================================================
#  模糊密码生成器 (Fuzzy Password)
# ============================================================
def parse_mask(mask_str):
    """
    解析掩码字符串并返回迭代所需的字符池列表。
    支持的占位符:
      ?d = 数字 (0-9)
      ?l = 小写字母 (a-z)
      ?u = 大写字母 (A-Z)
      ?a = 全部字母 (a-zA-Z)
      ?s = 符号
      ?x = 全部字符 (字母+数字+符号)
    普通字符保持原样。
    """
    pools = []
    i = 0
    while i < len(mask_str):
        if mask_str[i] == '?' and i + 1 < len(mask_str):
            kind = mask_str[i+1]
            if kind == 'd':
                pools.append(list(string.digits))
            elif kind == 'l':
                pools.append(list(string.ascii_lowercase))
            elif kind == 'u':
                pools.append(list(string.ascii_uppercase))
            elif kind == 'a':
                pools.append(list(string.ascii_letters))
            elif kind == 's':
                pools.append(list("!@#$%^&*()-_=+[]{}|;:',.<>?/`~"))
            elif kind == 'x':
                pools.append(list(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"))
            elif kind == '?':
                pools.append(['?'])
            else:
                # 原样保留
                pools.append([mask_str[i:i+2]])
            i += 2
        else:
            pools.append([mask_str[i]])
            i += 1
    return pools

def _get_case_variants(word):
    if not word: return [""]
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    return list(variants)

def _generate_fragment_combinations(fragments, add_common_suffixes=True):
    """把零散碎片生成多种可能拼接情况，并可选增加常见后缀"""
    valid_frags = [f.strip() for f in fragments if f.strip()]
    if not valid_frags:
        yield ""
        return
        
    linkers = ["", "-", "_", ".", " "]
    
    # 基础的拼接组合
    base_results = set()
    for perm in itertools.permutations(valid_frags):
        # 对每一个 permutation，每个片段有不同的 case variant 
        variant_pools = [_get_case_variants(w) for w in perm]
        for variant_combo in itertools.product(*variant_pools):
            # 对变体进行不同的连接符组合
            if len(variant_combo) == 1:
                base_results.add(variant_combo[0])
            else:
                spaces = len(variant_combo) - 1
                linker_pools = [linkers for _ in range(spaces)]
                for linker_combo in itertools.product(*linker_pools):
                    res = ""
                    for i in range(spaces):
                        res += variant_combo[i] + linker_combo[i]
                    res += variant_combo[-1]
                    base_results.add(res)
                    
    # 如果允许添加常见后缀（通常在没有 mask 时开启，让独立碎片变体更多）
    if add_common_suffixes:
        common_suffixes = ["", "123", "1234", "12345", "123456", "111", "666", "888", "999", "000"]
        # 添加近几年的年份
        for y in range(1980, 2026):
            common_suffixes.append(str(y))
            # 两位数年份
            common_suffixes.append(str(y)[2:])
            
        for base in base_results:
            for suf in common_suffixes:
                if suf:
                    yield base + suf
                    yield base + "_" + suf
                    yield base + "@" + suf
                else:
                    yield base
    else:
        for base in base_results:
            yield base

def calc_fuzzy_combinations(fragments, mask_str):
    """计算模糊密码的预计组合数"""
    frag_count = 1
    if fragments:
        valid_frags = [f.strip() for f in fragments if f.strip()]
        if valid_frags:
            import math
            frag_perms = math.factorial(len(valid_frags))
            linkers_variants = 5 ** max(0, len(valid_frags) - 1)
            case_variants = 3 ** len(valid_frags)
            frag_count = frag_perms * linkers_variants * case_variants
            # 如果没有 mask_str，则会挂载大约 150 个后缀组合 (50 个后缀 * 3 个前缀符)
            if not mask_str:
                frag_count *= 150

    if mask_str:
        pools = parse_mask(mask_str)
        mask_count = 1
        for p in pools:
            mask_count *= len(p)
        total = frag_count * mask_count
    else:
        total = frag_count
        
    return total

def fuzzy_generator(fragments, mask_str):
    """联合生成模糊密码。"""
    # 如果没有 mask，说明纯靠 fragment 盲猜，开启 common_suffixes 扩展
    add_suffixes = not bool(mask_str)
    
    # 1. 片段生成
    frag_gen = _generate_fragment_combinations(fragments, add_suffixes) if fragments else [""]
    # 2. 掩码生成
    mask_pools = parse_mask(mask_str) if mask_str else []
    
    frag_list = list(frag_gen)
    
    if not mask_pools:
        # 只生成片段
        for f in frag_list:
            if f: yield f
        return

    # 生成 mask 的乘积
    for combo in itertools.product(*mask_pools):
        m_res = "".join(combo)
        if not frag_list or (len(frag_list) == 1 and frag_list[0] == ""):
            yield m_res
        else:
            # 简单把片段放前面、中间(如果可能有)和后面
            for f in frag_list:
                yield f + m_res
                if m_res:
                    yield m_res + f
                    yield m_res + f
#  格式化工具
# ============================================================
def format_time(seconds):
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
    if n < 1000:
        return str(n)
    elif n < 1_000_000:
        return f"{n/1000:.1f}K"
    elif n < 1_000_000_000:
        return f"{n/1_000_000:.1f}M"
    else:
        return f"{n/1_000_000_000:.1f}B"


# ============================================================
#  破解会话管理器
# ============================================================
class CrackSession:
    """
    管理一次破解会话的全生命周期。
    支持进度回调、取消、断点续破。
    """

    def __init__(self, zip_path, use_pyzipper=False, workers=None):
        self.zip_path = zip_path
        self.use_pyzipper = use_pyzipper
        self.workers = workers or multiprocessing.cpu_count()
        self.archive_type = detect_archive_type(zip_path)
        # 7z 不需要 test_files，每次都 readall
        self.test_files = get_test_files(zip_path, use_pyzipper) if self.archive_type == 'zip' else None

        # 状态
        self.running = False
        self.cancel_requested = False
        self.result = None
        self.error = None

        # 进度信息
        self.phase = ""
        self.tried = 0
        self.total = 0
        self.speed = 0
        self.current_pwd = ""
        self.start_time = 0
        self.elapsed = 0
        self.eta = 0

        # 断点续破
        self.checkpoint_dir = os.path.join(os.path.dirname(zip_path), ".zipcrack_checkpoints")
        self.checkpoint_file = os.path.join(
            self.checkpoint_dir,
            os.path.basename(zip_path) + ".checkpoint.json"
        )

        # 回调
        self._progress_callback = None

    def on_progress(self, callback):
        """注册进度回调: callback(session)"""
        self._progress_callback = callback

    def _notify(self):
        """触发进度通知"""
        if self._progress_callback:
            try:
                self._progress_callback(self)
            except Exception:
                pass

    def _update_progress(self, tried, total, phase, current_pwd=""):
        elapsed = time.time() - self.start_time
        self.tried = tried
        self.total = total
        self.phase = phase
        self.current_pwd = current_pwd
        self.elapsed = elapsed
        self.speed = tried / elapsed if elapsed > 0 else 0
        if total > 0 and self.speed > 0:
            self.eta = (total - tried) / self.speed
        else:
            self.eta = 0
        self._notify()

    def get_progress_dict(self):
        """获取当前进度的字典形式（用于 API 返回）"""
        pct = 0
        if self.total > 0:
            pct = min(self.tried / self.total * 100, 100)
        return {
            "running": self.running,
            "phase": self.phase,
            "tried": self.tried,
            "total": self.total,
            "percent": round(pct, 2),
            "speed": round(self.speed, 1),
            "speed_fmt": format_number(int(self.speed)) + "/秒",
            "current_pwd": self.current_pwd[:30],
            "elapsed": round(self.elapsed, 1),
            "elapsed_fmt": format_time(self.elapsed),
            "eta": round(self.eta, 1),
            "eta_fmt": format_time(self.eta),
            "result": self.result,
            "error": self.error,
            "cancel_requested": self.cancel_requested,
        }

    # ---- 断点续破 ----
    def _save_checkpoint(self, phase, batch_index, config):
        """保存断点"""
        try:
            os.makedirs(self.checkpoint_dir, exist_ok=True)
            data = {
                "zip_path": self.zip_path,
                "phase": phase,
                "batch_index": batch_index,
                "tried": self.tried,
                "config": config,
                "timestamp": time.time(),
            }
            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _load_checkpoint(self):
        """加载断点"""
        try:
            if os.path.exists(self.checkpoint_file):
                with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if data.get("zip_path") == self.zip_path:
                    return data
        except Exception:
            pass
        return None

    def _clear_checkpoint(self):
        """清除断点"""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
        except Exception:
            pass

    def has_checkpoint(self):
        """是否有可恢复的断点"""
        cp = self._load_checkpoint()
        return cp is not None

    def get_checkpoint_info(self):
        """获取断点信息"""
        return self._load_checkpoint()

    # ---- 攻击方法 ----
    def cancel(self):
        self.cancel_requested = True

    def dict_attack(self, passwords, label="字典攻击", start_index=0):
        """字典攻击"""
        if not passwords:
            return None

        total = len(passwords)
        self.start_time = time.time()
        self._update_progress(start_index, total, label)

        if self.archive_type == '7z':
            batch_size = max(5, min(50, total // (self.workers * 4)))
        else:
            batch_size = max(200, total // (self.workers * 4))
        result = None
        tried = start_index

        try:
            with Pool(processes=self.workers) as pool:
                batches = []
                for i in range(start_index, total, batch_size):
                    batch = passwords[i:i + batch_size]
                    batches.append((self.zip_path, batch, self.use_pyzipper, self.test_files, self.archive_type))

                async_results = pool.imap_unordered(try_batch, batches)
                batch_idx = 0
                for res in async_results:
                    if self.cancel_requested:
                        pool.terminate()
                        self._save_checkpoint(label, tried, {"type": "dict"})
                        return None

                    tried += batch_size
                    tried = min(tried, total)
                    current = passwords[min(tried, total) - 1] if tried > 0 else ""
                    self._update_progress(tried, total, label, current)

                    # 每 10 批保存一次断点
                    batch_idx += 1
                    if batch_idx % 10 == 0:
                        self._save_checkpoint(label, tried, {"type": "dict"})

                    if res is not None:
                        if verify_password(self.zip_path, res, self.use_pyzipper, archive_type=self.archive_type):
                            result = res
                            pool.terminate()
                            break
        except KeyboardInterrupt:
            self._save_checkpoint(label, tried, {"type": "dict"})
            return None

        return result

    def bruteforce_attack(self, charset_name="digits", min_len=1, max_len=6):
        """暴力破解攻击"""
        charset = CHARSETS.get(charset_name, charset_name)
        total = calc_total_combinations(len(charset), min_len, max_len)
        label = f"暴力破解 [{CHARSET_LABELS.get(charset_name, charset_name)}]"

        self.start_time = time.time()
        if self.archive_type == '7z':
            # 7z KDF 极慢，单次尝试需要 ~0.08s，batch 过大会导致进度条冻结
            batch_size = max(20, min(500, total // (self.workers * 4)))
        else:
            batch_size = max(1000, min(200000, total // (self.workers * 10)))

        result = None
        tried = 0
        self._update_progress(0, total, label)

        try:
            with Pool(processes=self.workers) as pool:
                gen = bruteforce_generator(charset, min_len, max_len)
                batch_idx = 0

                while True:
                    if self.cancel_requested:
                        pool.terminate()
                        self._save_checkpoint(label, tried, {
                            "type": "bruteforce",
                            "charset_name": charset_name,
                            "min_len": min_len,
                            "max_len": max_len,
                        })
                        return None

                    batch = list(itertools.islice(gen, batch_size))
                    if not batch:
                        break

                    current_pwd_display = batch[0]

                    if self.archive_type == '7z':
                        sub_batch_size = max(2, len(batch) // self.workers)
                    else:
                        sub_batch_size = max(100, len(batch) // self.workers)
                    sub_batches = []
                    for i in range(0, len(batch), sub_batch_size):
                        sub = batch[i:i + sub_batch_size]
                        sub_batches.append((self.zip_path, sub, self.use_pyzipper, self.test_files, self.archive_type))

                    async_results = pool.map_async(try_batch, sub_batches)

                    while not async_results.ready():
                        self._update_progress(tried, total, label, current_pwd_display)
                        async_results.wait(1.0)

                    for res in async_results.get():
                        if res is not None:
                            if verify_password(self.zip_path, res, self.use_pyzipper, archive_type=self.archive_type):
                                result = res
                                pool.terminate()
                                break

                    tried += len(batch)
                    self._update_progress(tried, total, label, current_pwd_display)

                    batch_idx += 1
                    if batch_idx % 20 == 0:
                        self._save_checkpoint(label, tried, {
                            "type": "bruteforce",
                            "charset_name": charset_name,
                            "min_len": min_len,
                            "max_len": max_len,
                        })

                    if result:
                        break

        except KeyboardInterrupt:
            self._save_checkpoint(label, tried, {
                "type": "bruteforce",
                "charset_name": charset_name,
                "min_len": min_len,
                "max_len": max_len,
            })
            return None

        return result

    def auto_attack(self, dict_file=None, charset_name=None, min_len=1, max_len=6):
        """
        自动递进模式。
        如果指定了 charset_name，则只使用该字符集进行暴力破解。
        """
        self.running = True
        self.cancel_requested = False
        self.result = None
        self.error = None

        try:
            # 阶段1: 内置字典
            self.phase = "阶段1: 内置常用密码字典"
            self._update_progress(0, len(BUILTIN_PASSWORDS), self.phase)
            result = self.dict_attack(BUILTIN_PASSWORDS, self.phase)
            if result:
                self.result = result
                return result
            if self.cancel_requested:
                return None

            # 阶段2: 外部字典
            if dict_file and os.path.exists(dict_file):
                try:
                    with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                        ext_passwords = [line.strip() for line in f if line.strip()]
                    self.phase = "阶段2: 外部字典攻击"
                    result = self.dict_attack(ext_passwords, self.phase)
                    if result:
                        self.result = result
                        return result
                    if self.cancel_requested:
                        return None
                except Exception as e:
                    self.error = f"无法读取字典文件: {e}"

            if charset_name:
                # 用户指定了字符集
                self.phase = f"暴力破解 [{CHARSET_LABELS.get(charset_name, charset_name)}]"
                result = self.bruteforce_attack(charset_name, min_len, max_len)
                if result:
                    self.result = result
                    return result
            else:
                # 全自动递进
                stages = [
                    ("digits", 1, 8),
                    ("alnum", 1, 5),
                    ("alnumcase", 1, 4),
                    ("all", 1, 4),
                ]
                for cs, mn, mx in stages:
                    if self.cancel_requested:
                        return None
                    result = self.bruteforce_attack(cs, mn, mx)
                    if result:
                        self.result = result
                        return result

            return None

        except Exception as e:
            self.error = str(e)
            return None
        finally:
            self.running = False
            self._clear_checkpoint()
            self._notify()

    def single_bruteforce(self, charset_name, min_len, max_len):
        """单独执行暴力破解（不走自动递进）"""
        self.running = True
        self.cancel_requested = False
        self.result = None
        self.error = None

        try:
            result = self.bruteforce_attack(charset_name, min_len, max_len)
            if result:
                self.result = result
            return result
        except Exception as e:
            self.error = str(e)
            return None
        finally:
            self.running = False
            self._clear_checkpoint()
            self._notify()

    def single_dict_attack(self, passwords, label="字典攻击"):
        """单独执行字典攻击"""
        self.running = True
        self.cancel_requested = False
        self.result = None
        self.error = None

        try:
            result = self.dict_attack(passwords, label)
            if result:
                self.result = result
            return result
        except Exception as e:
            self.error = str(e)
            return None
        finally:
            self.running = False
            self._clear_checkpoint()
            self._notify()

    def fuzzy_attack(self, fragments, mask_str, label="模糊破解"):
        """使用记忆碎片或掩码生成密码进行破解"""
        self.running = True
        self.cancel_requested = False
        self.result = None
        self.error = None

        total = calc_fuzzy_combinations(fragments, mask_str)
        self.start_time = time.time()
        self._update_progress(0, total, label)

        if self.archive_type == '7z':
            batch_size = max(20, min(500, total // (self.workers * 4)))
        else:
            batch_size = max(1000, min(100000, total // (self.workers * 10)))

        result = None
        tried = 0

        try:
            with multiprocessing.Pool(processes=self.workers) as pool:
                gen = fuzzy_generator(fragments, mask_str)
                batch_idx = 0

                while True:
                    if self.cancel_requested:
                        pool.terminate()
                        self._save_checkpoint(label, tried, {"type": "fuzzy"})
                        return None

                    batch = list(itertools.islice(gen, batch_size))
                    if not batch:
                        break

                    current_pwd_display = batch[0]

                    if self.archive_type == '7z':
                        sub_batch_size = max(2, len(batch) // self.workers)
                    else:
                        sub_batch_size = max(100, len(batch) // self.workers)
                        
                    sub_batches = []
                    for i in range(0, len(batch), sub_batch_size):
                        sub = batch[i:i + sub_batch_size]
                        sub_batches.append((self.zip_path, sub, self.use_pyzipper, self.test_files, self.archive_type))

                    async_results = pool.map_async(try_batch, sub_batches)

                    while not async_results.ready():
                        self._update_progress(tried, total, label, current_pwd_display)
                        async_results.wait(1.0)

                    for res in async_results.get():
                        if res is not None:
                            if verify_password(self.zip_path, res, self.use_pyzipper, archive_type=self.archive_type):
                                result = res
                                pool.terminate()
                                break

                    tried += len(batch)
                    self._update_progress(tried, total, label, current_pwd_display)

                    batch_idx += 1
                    if batch_idx % 20 == 0:
                        self._save_checkpoint(label, tried, {"type": "fuzzy"})

                    if result:
                        break

        except KeyboardInterrupt:
            self._save_checkpoint(label, tried, {"type": "fuzzy"})
            return None
        except Exception as e:
            self.error = str(e)
            return None
        finally:
            self.running = False
            self._clear_checkpoint()
            self._notify()

        if result:
            self.result = result
        return result


# ============================================================
#  模糊密码生成器
# ============================================================
class FuzzyGenerator:
    """
    根据用户提供的记忆碎片/掩码，生成优先候选密码列表。

    掩码语法: ?d=数字 ?l=小写 ?u=大写 ?a=字母 ?s=符号 ?=全部
    碎片模式: 输入若干片段，自动组合各种排列和变体
    """

    # 掩码字符映射
    MASK_MAP = {
        'd': string.digits,
        'l': string.ascii_lowercase,
        'u': string.ascii_uppercase,
        'a': string.ascii_letters,
        's': "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",
    }
    MASK_ALL = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

    MAX_CANDIDATES = 1_000_000  # 候选上限

    @staticmethod
    def parse_mask(mask_str):
        """
        解析掩码字符串，返回每个位置对应的字符集列表。
        例如 'abc?d?d' → [['a'], ['b'], ['c'], ['0'..'9'], ['0'..'9']]
        """
        positions = []
        i = 0
        while i < len(mask_str):
            if mask_str[i] == '?' and i + 1 < len(mask_str):
                next_char = mask_str[i + 1]
                if next_char in FuzzyGenerator.MASK_MAP:
                    positions.append(list(FuzzyGenerator.MASK_MAP[next_char]))
                    i += 2
                    continue
                elif next_char == '?':
                    # ?? = 全部字符
                    positions.append(list(FuzzyGenerator.MASK_ALL))
                    i += 2
                    continue
            # 普通字符
            positions.append([mask_str[i]])
            i += 1
        return positions

    @staticmethod
    def generate_from_mask(mask_str, limit=None):
        """根据掩码生成所有密码组合"""
        if limit is None:
            limit = FuzzyGenerator.MAX_CANDIDATES
        positions = FuzzyGenerator.parse_mask(mask_str)
        if not positions:
            return []

        # 计算总组合数
        total = 1
        for p in positions:
            total *= len(p)
            if total > limit:
                break

        results = []
        count = 0
        for combo in itertools.product(*positions):
            results.append(''.join(combo))
            count += 1
            if count >= limit:
                break
        return results

    @staticmethod
    def count_mask_combinations(mask_str):
        """计算掩码会生成多少组合"""
        positions = FuzzyGenerator.parse_mask(mask_str)
        total = 1
        for p in positions:
            total *= len(p)
            if total > 10**15:
                return total  # 太大了直接返回
        return total

    @staticmethod
    def expand_fragments(fragments, max_total=None):
        """
        根据碎片列表生成各种组合和变体。
        fragments: ['love', '123'] → love123, 123love, Love123, LOVE123, love_123...
        """
        if max_total is None:
            max_total = FuzzyGenerator.MAX_CANDIDATES

        if not fragments:
            return []

        # 清理碎片
        fragments = [f.strip() for f in fragments if f.strip()]
        if not fragments:
            return []

        seen = set()
        results = []

        def add(pwd):
            if pwd and pwd not in seen and len(results) < max_total:
                seen.add(pwd)
                results.append(pwd)

        # 1. 每个碎片本身及其变体
        for frag in fragments:
            add(frag)
            add(frag.lower())
            add(frag.upper())
            add(frag.capitalize())
            add(frag.swapcase())
            # 常见 leet speak 替换
            leet = frag.lower().replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
            add(leet)

        # 2. 两两排列组合
        from itertools import permutations
        for perm in permutations(fragments, min(len(fragments), 4)):
            # 直接拼接
            add(''.join(perm))
            # 带常见分隔符
            for sep in ['_', '.', '-', '@', '#']:
                add(sep.join(perm))

            # 每个碎片的大小写变体组合
            base = ''.join(perm)
            add(base.lower())
            add(base.upper())
            add(base.capitalize())

        # 3. 碎片 + 常见后缀/前缀
        common_suffixes = [
            '', '1', '12', '123', '1234', '12345', '123456',
            '0', '00', '000', '01', '02',
            '!', '!!', '@', '#', '$',
            '666', '888', '999', '520', '1314',
            '2024', '2025', '2026',
        ]
        common_prefixes = ['', '1', '123', 'a', 'my', 'the', 'i']

        for frag in fragments:
            for suffix in common_suffixes:
                add(frag + suffix)
                add(frag.capitalize() + suffix)
                add(frag.upper() + suffix)
            for prefix in common_prefixes:
                add(prefix + frag)
                add(prefix + frag.capitalize())

        # 4. 两碎片组合 + 后缀
        if len(fragments) >= 2:
            for i in range(len(fragments)):
                for j in range(len(fragments)):
                    if i == j:
                        continue
                    combo = fragments[i] + fragments[j]
                    for suffix in common_suffixes[:10]:
                        add(combo + suffix)
                        add(combo.capitalize() + suffix)

        return results

    @staticmethod
    def generate_priority_list(fragments=None, masks=None, max_total=None):
        """
        综合生成优先密码列表。
        fragments: 碎片列表
        masks: 掩码列表
        返回: (密码列表, 总数)
        """
        if max_total is None:
            max_total = FuzzyGenerator.MAX_CANDIDATES

        all_passwords = []
        seen = set()

        def add_list(passwords):
            for p in passwords:
                if p not in seen and len(all_passwords) < max_total:
                    seen.add(p)
                    all_passwords.append(p)

        # 1. 碎片展开
        if fragments:
            expanded = FuzzyGenerator.expand_fragments(fragments, max_total)
            add_list(expanded)

        # 2. 掩码展开
        if masks:
            remaining = max_total - len(all_passwords)
            for mask in masks:
                if remaining <= 0:
                    break
                mask_passwords = FuzzyGenerator.generate_from_mask(mask, remaining)
                add_list(mask_passwords)
                remaining = max_total - len(all_passwords)

        return all_passwords, len(all_passwords)

