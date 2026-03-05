#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIP 密码破解工具 - Web 服务
============================
Flask 后端，通过 subprocess 启动独立破解进程，
读取 JSON 进度文件并通过 SSE 推送给前端。

启动方式: python app.py
访问: http://localhost:5000
"""

import json
import os
import subprocess
import sys
import time
import multiprocessing
import uuid

from flask import Flask, request, jsonify, Response, render_template  # type: ignore

# 本地导入（仅用于检测/字典等非 CPU 密集操作）
from cracker_core import (  # type: ignore
    BUILTIN_PASSWORDS,
    CHARSETS,
    CHARSET_LABELS,
    FuzzyGenerator,
    detect_encryption,
    format_number,
)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB

# 目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DICT_DIR = os.path.join(BASE_DIR, "dictionaries")
WORK_DIR = os.path.join(BASE_DIR, ".worker_data")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DICT_DIR, exist_ok=True)
os.makedirs(WORK_DIR, exist_ok=True)

# 全局 worker 进程引用
worker_process = None
progress_file_path = ""
control_file_path = ""


def _slice(obj, start, end):
    """Helper to avoid Pyre2 false positives on slicing."""
    import operator
    return operator.getitem(obj, slice(start, end))


def format_file_size(size):
    """格式化文件大小"""
    s = int(size)
    if s < 1024:
        return f"{s} B"
    elif s < 1024 * 1024:
        return f"{s / 1024:.1f} KB"
    elif s < 1024 * 1024 * 1024:
        return f"{s / (1024 * 1024):.1f} MB"
    else:
        return f"{s / (1024 * 1024 * 1024):.1f} GB"


def read_progress():
    """从 JSON 文件读取 worker 进度"""
    global progress_file_path, worker_process
    default = {
        "running": False,
        "phase": "等待开始",
        "tried": 0,
        "total": 0,
        "percent": 0.0,
        "speed": 0,
        "speed_fmt": "0/秒",
        "current_pwd": "",
        "elapsed": 0,
        "elapsed_fmt": "0秒",
        "eta": 0,
        "eta_fmt": "-",
        "result": None,
        "error": None,
        "cancel_requested": False,
    }

    if not progress_file_path or not os.path.exists(progress_file_path):
        return default

    try:
        with open(progress_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 检查 worker 进程是否还活着
        if worker_process is not None:
            ret = worker_process.poll()
            if ret is not None:
                # 进程已结束
                data["running"] = False
                worker_process = None
        else:
            # 如果 Flask 这边认为进程没了，就强制标记停止
            data["running"] = False

        return data
    except (json.JSONDecodeError, IOError):
        return default


# ============================================================
#  页面路由
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
#  API: 系统信息
# ============================================================
@app.route("/api/system")
def system_info():
    cpu_count = multiprocessing.cpu_count()
    charsets_info = {}
    for k, v in CHARSETS.items():
        v_str = str(v)
        preview = _slice(v_str, 0, 40)
        charsets_info[k] = {
            "label": CHARSET_LABELS.get(k, k),
            "size": len(v_str),
            "preview": preview,
        }
    return jsonify(
        {
            "cpu_count": cpu_count,
            "charsets": charsets_info,
            "builtin_dict_size": len(BUILTIN_PASSWORDS),
        }
    )


# ============================================================
#  API: 上传 ZIP 文件
# ============================================================
@app.route("/api/upload", methods=["POST"])
def upload_zip():
    if "file" not in request.files:
        return jsonify({"error": "没有选择文件"}), 400

    file = request.files["file"]
    if file.filename == "" or file.filename is None:
        return jsonify({"error": "文件名为空"}), 400

    filename = str(file.filename)
    hex_id = uuid.uuid4().hex
    safe_name = f"{_slice(hex_id, 0, 8)}_{filename}"
    filepath = os.path.join(UPLOAD_DIR, safe_name)
    file.save(filepath)

    info = detect_encryption(filepath)
    info["filename"] = filename
    info["filepath"] = filepath
    info["filesize"] = os.path.getsize(filepath)
    info["filesize_fmt"] = format_file_size(info["filesize"])

    if info.get("needs_pyzipper"):
        try:
            import pyzipper  # type: ignore  # noqa: F401

            info["pyzipper_available"] = True
        except ImportError:
            info["pyzipper_available"] = False

    return jsonify(info)


# ============================================================
#  API: 字典管理
# ============================================================
@app.route("/api/dictionaries", methods=["GET"])
def list_dictionaries():
    dicts = []
    for f in os.listdir(DICT_DIR):
        if f.endswith(".txt"):
            fpath = os.path.join(DICT_DIR, f)
            size = os.path.getsize(fpath)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    line_count = sum(1 for line in fh if line.strip())
            except Exception:
                line_count = 0
            dicts.append(
                {
                    "name": f,
                    "path": fpath,
                    "size": size,
                    "size_fmt": format_file_size(size),
                    "line_count": line_count,
                    "line_count_fmt": format_number(line_count),
                }
            )
    return jsonify(dicts)


@app.route("/api/dictionaries", methods=["POST"])
def upload_dictionary():
    if "file" not in request.files:
        return jsonify({"error": "没有选择文件"}), 400

    file = request.files["file"]
    if file.filename == "" or file.filename is None:
        return jsonify({"error": "文件名为空"}), 400

    filename = str(file.filename)
    if not filename.endswith(".txt"):
        filename += ".txt"

    filepath = os.path.join(DICT_DIR, filename)
    file.save(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            line_count = sum(1 for line in fh if line.strip())
    except Exception:
        line_count = 0

    return jsonify(
        {
            "name": filename,
            "path": filepath,
            "size": os.path.getsize(filepath),
            "size_fmt": format_file_size(os.path.getsize(filepath)),
            "line_count": line_count,
            "line_count_fmt": format_number(line_count),
        }
    )


@app.route("/api/dictionaries/<name>", methods=["DELETE"])
def delete_dictionary(name):
    filepath = os.path.join(DICT_DIR, name)
    if os.path.exists(filepath):
        os.remove(filepath)
        return jsonify({"ok": True})
    return jsonify({"error": "文件不存在"}), 404


# ============================================================
#  API: 模糊密码预览
# ============================================================
@app.route("/api/fuzzy_preview", methods=["POST"])
def fuzzy_preview():
    data = dict(request.json or {})
    fragments = data.get("fragments", [])
    masks = data.get("masks", "")

    if not fragments and not masks:
        return jsonify({"count": 0, "preview": []})

    from cracker_core import calc_fuzzy_combinations, fuzzy_generator
    total = calc_fuzzy_combinations(fragments, masks)

    gen = fuzzy_generator(fragments, masks)
    
    # 限制预览数量最大 20
    import itertools
    preview_list = list(itertools.islice(gen, 20))
    
    return jsonify(
        {
            "count": total,
            "preview_count": len(preview_list),
            "preview": preview_list,
        }
    )


# ============================================================
#  API: 开始破解（启动子进程）
# ============================================================
@app.route("/api/start", methods=["POST"])
def start_crack():
    global worker_process, progress_file_path, control_file_path

    # 检查是否已有 worker 在运行
    if worker_process is not None and worker_process.poll() is None:
        return jsonify({"error": "已有任务正在运行"}), 409

    data = dict(request.json or {})
    zip_path = str(data.get("zip_path", ""))

    if not zip_path or not os.path.exists(zip_path):
        return jsonify({"error": "ZIP 文件不存在"}), 400

    # 生成工作文件路径
    hex_id = uuid.uuid4().hex
    task_id = _slice(hex_id, 0, 12)
    progress_file_path = os.path.join(WORK_DIR, f"progress_{task_id}.json")
    control_file_path = os.path.join(WORK_DIR, f"control_{task_id}.txt")
    config_file = os.path.join(WORK_DIR, f"config_{task_id}.json")

    # 清理旧文件
    for path in [progress_file_path, control_file_path, config_file]:
        if os.path.exists(path):
            os.remove(path)

    # 写入配置
    config = {
        "zip_path": zip_path,
        "mode": data.get("mode", "auto"),
        "charset": data.get("charset", "digits"),
        "min_len": int(data.get("min_len", 1)),
        "max_len": int(data.get("max_len", 6)),
        "workers": int(data.get("workers", multiprocessing.cpu_count())),
        "use_pyzipper": data.get("use_pyzipper", False),
        "dict_file": data.get("dict_file"),
        "progress_file": progress_file_path,
        "control_file": control_file_path,
        "fragments": data.get("fragments", []),
        "masks": data.get("masks", []),
    }

    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    # 写初始进度
    with open(progress_file_path, "w", encoding="utf-8") as f:
        json.dump({"running": True, "phase": "Starting...", "tried": 0, "total": 0,
                    "percent": 0, "speed": 0, "speed_fmt": "0/秒", "current_pwd": "",
                    "elapsed": 0, "elapsed_fmt": "0秒", "eta": 0, "eta_fmt": "-",
                    "result": None, "error": None, "cancel_requested": False}, f)

    # 启动独立 worker 进程
    python_exe = sys.executable
    worker_script = os.path.join(BASE_DIR, "cracker_worker.py")

    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    worker_process = subprocess.Popen(
        [python_exe, worker_script, config_file],
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creation_flags,
    )

    return jsonify({"ok": True, "message": "Task started", "task_id": task_id})


# ============================================================
#  API: 停止任务
# ============================================================
@app.route("/api/stop", methods=["POST"])
def stop_crack():
    global worker_process, control_file_path

    proc = worker_process
    if proc is None or proc.poll() is not None:
        return jsonify({"error": "没有正在运行的任务"}), 404

    # 发送停止信号：写控制文件
    try:
        with open(control_file_path, "w") as f:
            f.write("stop")
    except Exception:
        pass

    # 给 worker 一些时间来优雅退出
    try:
        proc.wait(timeout=3)  # type: ignore
    except subprocess.TimeoutExpired:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc.kill()  # type: ignore

    worker_process = None
    return jsonify({"ok": True, "message": "Task stopped"})


# ============================================================
#  API: SSE 进度流
# ============================================================
@app.route("/api/progress")
def progress_stream():
    def generate():
        while True:
            data = read_progress()
            yield f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            time.sleep(0.5)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================
#  启动
# ============================================================
if __name__ == "__main__":
    import io

    if sys.platform == "win32":
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace"
            )
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer, encoding="utf-8", errors="replace"
            )
        except Exception:
            pass

    multiprocessing.freeze_support()
    print("\n  ZIP Password Cracker - Web UI")
    print("  " + "=" * 40)
    print("  Open: http://localhost:5000")
    print("  " + "=" * 40 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
