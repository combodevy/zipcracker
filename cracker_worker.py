#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIP 密码破解 - 独立 Worker 进程
================================
由 app.py 通过 subprocess.Popen 启动，独立运行于主进程之外。
通过 JSON 文件与 Flask 交换进度信息。

用法（不要手动调用，由 app.py 自动管理）:
    python cracker_worker.py <config.json>
"""

import io
import json
import multiprocessing
import os
import sys
import time

# Fix Windows console encoding before any output
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

from cracker_core import (
    BUILTIN_PASSWORDS, CHARSETS, CrackSession, FuzzyGenerator,
    format_time, format_number
)


def main():
    if len(sys.argv) < 2:
        print("Usage: python cracker_worker.py <config.json>")
        sys.exit(1)

    config_path = sys.argv[1]
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    zip_path = config['zip_path']
    mode = config.get('mode', 'auto')
    charset = config.get('charset', 'digits')
    min_len = int(config.get('min_len', 1))
    max_len = int(config.get('max_len', 6))
    workers = int(config.get('workers', multiprocessing.cpu_count()))
    use_pyzipper = config.get('use_pyzipper', False)
    dict_file = config.get('dict_file')
    progress_file = config['progress_file']
    control_file = config.get('control_file', '')
    fragments = config.get('fragments', [])
    masks = config.get('masks', [])

    # 创建会话
    session = CrackSession(zip_path, use_pyzipper, workers)

    # 进度写入 JSON 文件的回调
    last_write_time = [0]

    def progress_callback(s):
        now = time.time()
        # 至少间隔 0.5 秒写一次，减少磁盘 IO
        if now - last_write_time[0] < 0.5:
            return
        last_write_time[0] = now

        data = s.get_progress_dict()
        try:
            tmp_path = progress_file + '.tmp'
            with open(tmp_path, 'w', encoding='utf-8') as pf:
                json.dump(data, pf, ensure_ascii=False)
            # 原子替换
            if os.path.exists(progress_file):
                os.remove(progress_file)
            os.rename(tmp_path, progress_file)
        except Exception:
            pass

        # 检查控制文件：是否需要停止
        if control_file and os.path.exists(control_file):
            try:
                with open(control_file, 'r') as cf:
                    cmd = cf.read().strip()
                if cmd == 'stop':
                    s.cancel()
            except Exception:
                pass

    session.on_progress(progress_callback)

    # ---- 执行攻击 ----
    try:
        if mode == 'fuzzy':
            session.phase = "模糊密码攻击"
            result = session.fuzzy_attack(fragments, masks, session.phase)
            if result:
                session.result = result
            session.running = False
        elif mode == 'auto':
            session.auto_attack(dict_file=dict_file, charset_name=charset,
                                min_len=min_len, max_len=max_len)
        elif mode == 'dict':
            passwords = list(BUILTIN_PASSWORDS)
            if dict_file and os.path.exists(dict_file):
                with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords.extend(line.strip() for line in f if line.strip())
            session.single_dict_attack(passwords, "字典攻击")
        elif mode == 'bruteforce':
            session.single_bruteforce(charset, min_len, max_len)

    except Exception as e:
        session.error = str(e)
        session.running = False

    # 写最终进度
    progress_callback(session)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()
