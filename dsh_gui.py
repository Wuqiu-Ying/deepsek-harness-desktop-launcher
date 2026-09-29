#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DSH Web GUI —— 一键启动 `npx @deepseek-ai/dsh web` 并显示 127.0.0.1:3080 界面

窗口模式 (自动降级):
  1. embedded  内嵌窗口: WebView2 直接嵌进本程序窗口, 真正的独立 GUI
               (需要 pywebview; 在受限沙箱进程中 pythonnet 会失败, 会自动降级)
  2. app       Edge 应用窗口: 无地址栏的独立窗口
  3. tab       系统默认浏览器标签页 (最后的兜底)

启动流程:
  1. 检测 127.0.0.1:3080 是否已有 DSH 服务; 有则直接复用, 不重复启动
  2. 否则后台执行  npx --yes @deepseek-ai/dsh web --no-open --port 3080
  3. 从服务输出中解析带 token 的启动地址
       dsh web: http://127.0.0.1:3080/?token=xxxx
     (该地址用于换取登录 Cookie; 直接打开根地址会返回 401)
  4. 用选定的窗口模式显示该地址
  5. 窗口关闭后, 自动结束本程序拉起的服务进程

依赖: Python 3.8+ 标准库 (tkinter) 即可运行; 内嵌模式额外需要 pywebview。

用法:
    python dsh_gui.py                  # 自动选择窗口模式
    python dsh_gui.py --mode embedded  # 强制内嵌窗口
    python dsh_gui.py --mode app       # 强制 Edge 应用窗口
    python dsh_gui.py --mode tab       # 系统默认浏览器
    python dsh_gui.py --port 3081      # 换端口
    python dsh_gui.py --keep-server    # 关闭窗口时保留后台服务

环境变量: DSH_GUI_PORT, DSH_GUI_TIMEOUT, DSH_GUI_KEEP_SERVER, DSH_GUI_LOG,
          DSH_GUI_PROFILE, DSH_GUI_MODE
"""

from __future__ import annotations

import argparse
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

APP_TITLE = "DSH Web GUI"
DEFAULT_PORT = 3080
DEFAULT_TIMEOUT = 180.0
URL_RE = re.compile(r"dsh web:\s*(https?://\S+)")

EDGE_PATHS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)

CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def probe(url: str, timeout: float = 1.5) -> int | None:
    """访问 url; 只要该端口有 HTTP 响应就返回状态码 (含 401/404 等), 否则 None。"""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (本机地址)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


def which_npx() -> str | None:
    """定位 npx (Windows 上优先 .cmd, 可被 subprocess 直接执行)。"""
    for name in ("npx.cmd", "npx.exe", "npx"):
        found = shutil.which(name)
        if found:
            return found
    return None


def find_edge() -> str | None:
    for cand in EDGE_PATHS:
        if Path(cand).is_file():
            return cand
    return None


def free_port() -> int:
    """向系统要一个当前空闲的端口。"""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def env_smoke_seconds() -> float:
    """自动化验证开关: DSH_GUI_SMOKE=<秒数> 时, 打开界面后自动收尾退出。"""
    raw = os.environ.get("DSH_GUI_SMOKE", "").strip()
    if not raw:
        return 0.0
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 0.0


def kill_tree(pid: int) -> None:
    """结束进程及其整棵子进程树 (npx -> node -> dsh server)。"""
    if pid <= 0:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
            timeout=20, check=False,
        )
    except Exception:
        pass


class JobGuard:
    """Windows 作业对象: 本进程被强杀时连带结束服务进程, 避免留下孤儿。"""

    def __init__(self) -> None:
        self.handle = None
        self.kernel32 = None
        if os.name != "nt":
            return
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                return

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                                    ctypes.sizeof(info)):
                return
            self.kernel32 = kernel32
            self.handle = job
        except Exception:
            self.handle = None

    def assign(self, proc: subprocess.Popen) -> None:
        if not self.handle or not self.kernel32:
            return
        try:
            self.kernel32.AssignProcessToJobObject(self.handle, int(proc._handle))  # noqa: SLF001
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 窗口后端探测
# --------------------------------------------------------------------------- #
def console_python() -> str:
    """返回一个带控制台的 Python 解释器路径。

    .pyw 由 pythonw.exe 执行, 而 pythonw 没有控制台: 用它启动的子进程 stdout
    不可靠。探测后端必须用一个能正常输出/回传结果的解释器。

    冻结成 exe 后没有外部解释器可用 (sys.executable 就是 exe 自己), 由调用方
    改用「exe 自身 + 子命令」的方式探测, 见 embedded_backend_error()。
    """
    if getattr(sys, "frozen", False):
        return sys.executable  # 调用方不会用到; 保留返回值以简化逻辑

    exe = Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        candidate = exe.with_name("python.exe")
        if candidate.is_file():
            return str(candidate)
    return sys.executable


# 冻结后用它作为子命令, 让 exe 自己充当探测子进程
INTERNAL_PROBE_FLAG = "--internal-probe-backend"

_PROBE_CODE = (
    "import sys\n"
    "path = sys.argv[1]\n"
    "try:\n"
    "    import webview.platforms.winforms  # noqa\n"
    "except BaseException:\n"
    "    import traceback\n"
    "    open(path, 'w', encoding='utf-8').write('BACKEND_FAIL\\n' + traceback.format_exc())\n"
    "    sys.exit(3)\n"
    "open(path, 'w', encoding='utf-8').write('BACKEND_OK')\n"
)


def run_internal_backend_probe(out_path: str) -> int:
    """冻结模式下的内嵌后端探测体: 结果写入 out_path, 不走 stdout。

    注意: 后端导入失败抛的不一定是 ImportError —— pythonnet 初始化失败时抛的是
    RuntimeError, 因此这里必须捕获 BaseException, 否则结果文件不会生成,
    父进程只会看到「探测无结果」。
    """
    try:
        import webview.platforms.winforms  # noqa: F401
    except BaseException:  # noqa: BLE001 - 任何失败都要回传原因
        import traceback

        text = "BACKEND_FAIL\n" + traceback.format_exc()
        exit_code = 3
    else:
        text = "BACKEND_OK"
        exit_code = 0
    try:
        Path(out_path).write_text(text, encoding="utf-8")
    except Exception:
        return 5
    return exit_code


def _probe_cache_path() -> Path:
    """探测结果的缓存文件位置 (按可执行文件路径与修改时间区分版本)。"""
    import hashlib

    if getattr(sys, "frozen", False):
        target = Path(sys.executable).resolve()
        try:
            stamp = str(int(target.stat().st_mtime))
        except Exception:
            stamp = "0"
        key = hashlib.sha256(f"{target}|{stamp}".encode("utf-8")).hexdigest()[:16]
    else:
        key = "script"
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DSH-GUI"
    return base / f"backend-probe-{key}.txt"


def embedded_backend_error(use_cache: bool = True) -> str | None:
    """检查内嵌窗口 (pywebview + WebView2) 后端是否可用: 可用返回 None, 否则返回原因。

    结果通过**临时文件**回传, 不依赖子进程的 stdout —— 双击 .pyw 时父进程是
    pythonw, 没有控制台, 管道 stdout 在某些组合下拿不到内容, 会造成误判。
    冻结成 exe 后没有外部解释器, 改为让 exe 自己带子命令充当探测子进程。

    冻结后每次探测都要重新解包整个 exe (约 3 秒), 因此结果会缓存; 缓存以可执行
    文件的路径+修改时间为键, 换新版本会自动失效。

    只探测后端模块能否导入, 不调用 webview.start() (后者会真的创建窗口)。
    放在子进程里探测还有个好处: pythonnet 初始化失败会把噪声打到 stderr 且不可恢复,
    让它发生在子进程里就不会污染本进程。
    """
    import tempfile

    # 冻结模式下才值得缓存 (脚本模式探测很快)
    cache = _probe_cache_path() if (use_cache and getattr(sys, "frozen", False)) else None
    if cache is not None:
        try:
            cached = cache.read_text(encoding="utf-8")
            if cached == "OK":
                return None
            if cached.startswith("FAIL\n"):
                return cached[5:].strip() or None
        except Exception:
            pass

    fd, out_path = tempfile.mkstemp(prefix="dsh-gui-probe-", suffix=".txt")
    os.close(fd)
    err_path = out_path + ".err"

    if getattr(sys, "frozen", False):
        cmd = [sys.executable, INTERNAL_PROBE_FLAG, out_path]
    else:
        cmd = [console_python(), "-X", "utf8", "-c", _PROBE_CODE, out_path]

    reason: str | None
    try:
        try:
            # stdout/stderr 都重定向到文件: 不依赖管道, 也避免子进程的非 UTF-8
            # 报错信息 (本地化异常文本) 把读取线程搞崩。
            with open(err_path, "wb") as errfh:
                subprocess.run(
                    cmd,
                    stdout=errfh, stderr=errfh, stdin=subprocess.DEVNULL,
                    timeout=120,
                    creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
                    check=False,
                )
        except Exception as exc:
            return f"探测失败: {exc}"

        text = ""
        for path in (out_path, err_path):
            try:
                text += Path(path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass
        if not text.strip():
            return "探测无结果 (子进程未回传)"
    finally:
        for path in (out_path, err_path):
            try:
                os.unlink(path)
            except Exception:
                pass

    reason = _interpret_probe(text)
    if cache is not None:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text("OK" if reason is None else f"FAIL\n{reason}", encoding="utf-8")
        except Exception:
            pass
    return reason


def _interpret_probe(text: str) -> str | None:
    """把探测子进程的输出解释成 None(可用) 或失败原因。"""
    if text.startswith("BACKEND_OK"):
        return None
    if "No module named" in text and "webview" in text:
        return "未安装 pywebview (pip install pywebview)"
    for line in reversed(text.strip().splitlines()):
        s = line.strip()
        if s.startswith(("RuntimeError:", "ImportError:", "OSError:", "WebViewException:")):
            return s
    if "pythonnet" in text or "Python.Runtime" in text:
        return "pythonnet 无法初始化 (受限进程或缺 WebView2 运行时)"
    return "后端不可用 (pythonnet/WebView2 初始化失败)"


def resolve_mode(requested: str, log=None) -> str:
    """决定最终窗口模式, 并在降级时说明原因。后端探测最多做一次。"""
    def note(msg: str) -> None:
        if log:
            log(msg)

    mode = requested
    if mode in ("auto", "embedded"):
        err = embedded_backend_error()
        if err is None:
            note("内嵌窗口后端可用, 使用内嵌窗口。")
            return "embedded"
        if mode == "embedded":
            note(f"内嵌窗口不可用, 改用 Edge 应用窗口。原因: {err}")
        else:
            note(f"内嵌窗口后端不可用, 改用 Edge 应用窗口。原因: {err}")
        mode = "app"

    if mode == "app" and not find_edge():
        note("未找到 Edge, 改用系统默认浏览器。")
        return "tab"
    return mode


# --------------------------------------------------------------------------- #
# 服务控制
# --------------------------------------------------------------------------- #
class ServerControl:
    """启动 / 等待 / 结束 `npx @deepseek-ai/dsh web`。"""

    def __init__(self, port: int, host: str, log, on_url):
        self.port = port
        self.host = host
        self.log = log
        self.on_url = on_url
        self.proc: subprocess.Popen | None = None
        self.spawned = False
        self.app_url: str | None = None
        self.job = JobGuard()

    @property
    def root_url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def _pump(self, stream) -> None:
        try:
            for raw in iter(stream.readline, b""):
                if not raw:
                    break
                text = raw.decode("utf-8", errors="replace").rstrip()
                if not text:
                    continue
                self.log(text)
                if self.app_url is None:
                    match = URL_RE.search(text)
                    if match:
                        self.app_url = match.group(1)
                        self.on_url(self.app_url)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def spawn(self) -> None:
        npx = which_npx()
        if not npx:
            raise RuntimeError(
                "找不到 npx 命令。\n\n"
                "请先安装 Node.js (https://nodejs.org/) 并确认 npx 已加入 PATH, "
                "然后重新运行本程序。"
            )

        cmd = [npx, "--yes", "@deepseek-ai/dsh", "web", "--no-open", "--port", str(self.port)]
        self.log("执行命令: " + " ".join(cmd))
        self.log("(首次运行需要下载 npm 包, 可能需要几分钟; --no-open 表示由本程序打开界面)")

        env = dict(os.environ)
        env.setdefault("NO_COLOR", "1")
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                cwd=str(Path.home()), env=env,
                creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except Exception as exc:
            raise RuntimeError(f"启动 dsh web 失败: {exc}") from exc

        self.spawned = True
        self.job.assign(self.proc)
        self.log(f"后台进程已启动 (pid={self.proc.pid})")
        threading.Thread(target=self._pump, args=(self.proc.stdout,), daemon=True).start()

    def wait_url(self, timeout: float) -> str | None:
        """等到服务打印出带 token 的地址。返回地址; 进程已退出则返回 ''。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.app_url:
                return self.app_url
            if self.exited() is not None:
                return self.app_url or ""
            time.sleep(0.4)
        return self.app_url

    def exited(self) -> int | None:
        return None if self.proc is None else self.proc.poll()

    def looks_like_dsh(self) -> bool:
        """dsh web 对未认证请求返回 401; 已登录则返回 200/302。"""
        return probe(self.root_url, timeout=3) in (200, 302, 303, 401)

    def stop(self) -> None:
        if self.spawned and self.proc is not None and self.proc.poll() is None:
            self.log("正在结束后台服务 …")
            kill_tree(self.proc.pid)
            try:
                self.proc.wait(timeout=10)
            except Exception:
                pass
            self.log("后台服务已结束")


class StartupError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# 启动器主体
# --------------------------------------------------------------------------- #
class Launcher:
    """启动服务并显示界面; 窗口部分按模式分派。"""

    def __init__(self, *, host: str, port: int, mode: str, timeout: float,
                 keep_server: bool, restart: bool, log_file: str | None):
        self.host, self.port = host, port
        self.mode = mode
        self.timeout, self.keep_server, self.restart = timeout, keep_server, restart
        self.log_file = log_file
        self._fh = self._open_log_file()

        self.messages: queue.Queue[tuple[str, str]] = queue.Queue()
        self.server = ServerControl(port, host, self.log, self._on_url)
        self.browser_proc: subprocess.Popen | None = None
        self.webview_window = None
        self.resolved_url: str | None = None
        self.resolved_fresh = False
        self.failed: str | None = None
        self.finished = False

        self.profile_dir = Path(
            os.environ.get("DSH_GUI_PROFILE")
            or (Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DSH-GUI" / "browser")
        )
        self.root = None  # tkinter 根窗口 (仅 app/tab 模式创建)

    # -- 日志 -------------------------------------------------------------- #
    def _open_log_file(self):
        if not self.log_file:
            return None
        try:
            path = Path(self.log_file).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            return open(path, "a", encoding="utf-8", buffering=1)
        except Exception:
            return None

    def log(self, text: str) -> None:
        self.messages.put(("log", text))
        if self._fh:
            try:
                self._fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
            except Exception:
                pass

    def _on_url(self, url: str) -> None:
        self.log(f"已获取带 token 的启动地址: {url}")

    def close_log(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    # -- 服务启动 (两种模式共用) ------------------------------------------- #
    def start_service(self) -> tuple[str, bool]:
        """启动或复用服务; 返回 (要打开的地址, 是否为新启动的实例)。

        关键点: 复用已有实例时拿不到一次性 token, 只能用根地址打开, 而那会 401。
        因此只有「根地址确实可访问(说明已有有效登录凭据)」才复用;
        否则改到一个空闲端口启动新实例, 这样总能拿到带 token 的地址。
        """
        root_url = self.server.root_url
        self.log(f"检查 {root_url} 是否已有服务 …")
        code = probe(root_url)

        if code is not None and self.server.looks_like_dsh():
            if 200 <= code < 300:
                self.log(f"该端口已有 DSH 服务且当前可正常访问 (HTTP {code}) -> 直接复用。")
                return root_url, False

            new_port = free_port()
            self.log(
                f"该端口已有 DSH 服务, 但未携带有效登录凭据 (HTTP {code}); "
                f"复用只能打开不带 token 的地址, 会显示未授权。"
            )
            self.log(f"改为在空闲端口 {new_port} 启动一个新实例, 这样可以自动完成认证。")
            self.server.port = new_port
            root_url = self.server.root_url

        elif code is not None:
            if not self.restart:
                raise StartupError(
                    f"端口 {self.port} 已被其它程序占用, 且响应内容不像 DSH 服务。\n\n"
                    f"请关闭占用该端口的程序后重试, 或换个端口:\n"
                    f"    python dsh_gui.py --port 3081"
                )
            self.log(f"警告: 端口 {self.port} 已被占用, 仍按 --restart 尝试启动。")

        self.server.spawn()
        url = self.server.wait_url(self.timeout)

        if url == "":
            code = self.server.exited()
            raise StartupError(
                f"dsh web 进程提前退出 (退出码 {code}), 未能启动服务。\n\n"
                "常见原因:\n"
                "  · Node.js 版本过低 (需要 Node 18 以上)\n"
                "  · 网络无法访问 npm 源, 依赖下载失败\n"
                "  · 端口被占用\n\n"
                "完整报错见启动日志。"
            )
        if not url:
            raise StartupError(
                f"等待 {int(self.timeout)} 秒后仍未拿到服务启动地址。\n\n"
                f"可增大超时: python dsh_gui.py --timeout 600"
            )

        self.log(f"服务就绪: {url}")
        return url, True

    def stop_server(self) -> None:
        if not self.server.spawned:
            return
        if self.keep_server:
            self.log("按设置保留后台服务 (--keep-server)。")
            return
        self.server.stop()

    # ===================================================================== #
    # 内嵌窗口模式
    # ===================================================================== #
    @staticmethod
    def _loading_page() -> str:
        return (
            "<!doctype html><html><head><meta charset='utf-8'><style>"
            "html,body{height:100%;margin:0;background:#0f1115;color:#e6e8eb;"
            "font:14px/1.7 'Microsoft YaHei UI',system-ui,sans-serif}"
            ".w{height:100%;display:flex;flex-direction:column;align-items:center;"
            "justify-content:center;gap:14px}"
            ".s{width:34px;height:34px;border:3px solid #2a2f3a;border-top-color:#4c8dff;"
            "border-radius:50%;animation:r 1s linear infinite}"
            "@keyframes r{to{transform:rotate(360deg)}}"
            "h1{font-size:17px;font-weight:600;margin:0}"
            "#d{color:#8b93a1;font-size:13px;max-width:560px;text-align:center;"
            "white-space:pre-wrap}"
            "</style></head><body><div class='w'><div class='s'></div>"
            "<h1>" + APP_TITLE + "</h1><div id='d'>正在启动服务 …</div></div>"
            "<script>function setStatus(t){document.getElementById('d').textContent=t}</script>"
            "</body></html>"
        )

    def _embed_update(self, text: str) -> None:
        """在内嵌窗口的占位页上更新状态文字。"""
        win = self.webview_window
        if win is None:
            return
        try:
            win.evaluate_js("setStatus(" + repr(text) + ")")
        except Exception:
            pass

    def run_embedded(self) -> int:
        """内嵌窗口模式: pywebview 必须占用主线程, 故在主线程启动。"""
        import webview

        self.webview_window = webview.create_window(
            APP_TITLE, html=self._loading_page(),
            width=1400, height=920, min_size=(900, 600), text_select=True,
        )
        win = self.webview_window
        self.log("内嵌窗口已创建, 正在启动服务 …")

        def on_loaded() -> None:
            self._embed_update("正在启动 dsh web 服务 …\n首次运行需要下载 npm 包, 请稍候。")

        try:
            win.events.loaded += on_loaded
        except Exception:
            pass

        smoke = env_smoke_seconds()
        if smoke:
            self.log(f"[smoke] {smoke} 秒后自动关闭窗口, 用于自动化验证")

            def auto_close() -> None:
                time.sleep(smoke)
                self.log("[smoke] 关闭内嵌窗口")
                try:
                    win.destroy()
                except Exception:
                    pass

            threading.Thread(target=auto_close, daemon=True).start()

        def worker() -> None:
            try:
                url, fresh = self.start_service()
            except Exception as exc:
                self.failed = str(exc)
                self.log("错误: " + str(exc).replace("\n", " "))
                self._embed_update("启动失败:\n" + str(exc))
                try:
                    win.set_title(APP_TITLE + " —— 启动失败")
                except Exception:
                    pass
                self.stop_server()
                return

            self.resolved_url, self.resolved_fresh = url, fresh
            if not fresh:
                self._embed_update(
                    "检测到已在运行的 DSH 服务, 正在打开 …\n\n"
                    "提示: 当前实例的登录凭据不在本窗口内, "
                    "若页面显示未授权, 请关闭本窗口后重新运行以启动新实例。"
                )
            self.log("正在内嵌窗口中打开界面 …")
            try:
                win.load_url(url)
            except Exception as exc:
                self.log(f"内嵌窗口加载失败: {exc}")
                self._embed_update(f"内嵌窗口加载失败: {exc}")

        threading.Thread(target=worker, daemon=True).start()

        try:
            webview.start()
        except Exception as exc:
            self.log(f"内嵌窗口启动失败: {exc}")
            print(f"内嵌窗口启动失败: {exc}", file=sys.stderr)
            self.stop_server()
            self.close_log()
            return 1

        self.log("内嵌窗口已关闭。")
        self.stop_server()
        self.close_log()
        return 1 if self.failed else 0

    # ===================================================================== #
    # tkinter 控制窗口 (app / tab 模式)
    # ===================================================================== #
    def run_tk(self) -> int:
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self._center(780, 470)
        self.root.minsize(640, 400)
        self.root.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self._build_ui()
        self.root.after(80, self._drain)
        self.root.after(150, self._begin)

        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._finish()
        return 1 if self.failed else 0

    def _center(self, w: int, h: int) -> None:
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")

    def _build_ui(self) -> None:
        tk, ttk = self.tk, self.ttk
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 15, "bold"))
        style.configure("Status.TLabel", font=("Microsoft YaHei UI", 10))
        style.configure("Hint.TLabel", font=("Microsoft YaHei UI", 9), foreground="#666666")

        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        self.sub_var = tk.StringVar(
            value=f"启动服务并打开 http://{self.host}:{self.port}/   窗口模式: {self.mode}")
        ttk.Label(outer, textvariable=self.sub_var, style="Hint.TLabel").pack(anchor="w", pady=(2, 10))

        self.status_var = tk.StringVar(value="准备中 …")
        ttk.Label(outer, textvariable=self.status_var, style="Status.TLabel").pack(anchor="w")

        self.bar = ttk.Progressbar(outer, mode="indeterminate")
        self.bar.pack(fill="x", pady=(8, 12))
        self.bar.start(12)

        box = ttk.LabelFrame(outer, text=" 启动日志 ", padding=6)
        box.pack(fill="both", expand=True)
        self.text = tk.Text(
            box, height=12, wrap="none", font=("Consolas", 9),
            background="#111418", foreground="#d7dae0", insertbackground="#d7dae0",
            relief="flat", borderwidth=0,
        )
        sb = ttk.Scrollbar(box, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(10, 0))
        self.hint_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.hint_var, style="Hint.TLabel").pack(side="left")
        self.btn = ttk.Button(bottom, text="取消并退出", command=self.on_cancel)
        self.btn.pack(side="right")

    def status(self, text: str) -> None:
        self.messages.put(("status", text))

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.messages.get_nowait()
                if kind == "log":
                    self.text.configure(state="normal")
                    self.text.insert("end", payload + "\n")
                    self.text.see("end")
                    self.text.configure(state="disabled")
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "sub":
                    self.sub_var.set(payload)
                elif kind == "hint":
                    self.hint_var.set(payload)
                elif kind == "fail":
                    self._on_failed(payload)
                    return
                elif kind == "close":
                    self._finish()
                    return
        except queue.Empty:
            pass
        if not self.finished:
            self.root.after(80, self._drain)

    def _begin(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        try:
            self.status("正在启动 dsh web 服务 …")
            url, fresh = self.start_service()
            self.resolved_url, self.resolved_fresh = url, fresh
            self._sync_port_label()
            self.status("服务已就绪, 正在打开界面 …")
            self._open_browser(url, fresh)
        except Exception as exc:
            self.messages.put(("fail", str(exc)))

    def _sync_port_label(self) -> None:
        """端口可能因为复用冲突而改变, 让界面显示真实端口。"""
        if self.resolved_url and self.server.port != self.port:
            self.messages.put((
                "hint",
                f"原端口 {self.port} 上已有服务但无有效凭据, 已改用端口 {self.server.port}",
            ))
            self.messages.put((
                "sub",
                f"启动服务并打开 {self.resolved_url.split('?')[0]}   "
                f"窗口模式: {self.mode}",
            ))

    def _open_browser(self, url: str, fresh: bool) -> None:
        if self.mode in ("app", "auto"):
            edge = find_edge()
            if edge:
                try:
                    self.profile_dir.mkdir(parents=True, exist_ok=True)
                except Exception as exc:
                    self.log(f"无法创建浏览器数据目录 ({exc}), 改用默认浏览器。")
                    edge = None
            if edge:
                if not fresh:
                    self.log("提示: 复用已有服务, 未携带一次性 token; 若显示未授权请重启本程序。")
                cmd = [
                    edge, f"--app={url}", f"--user-data-dir={self.profile_dir}",
                    "--no-first-run", "--no-default-browser-check", "--window-size=1400,920",
                ]
                self.log("以 Edge 应用窗口方式打开界面 (无地址栏的独立窗口)。")
                try:
                    self.browser_proc = subprocess.Popen(
                        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
                    )
                except Exception as exc:
                    self.log(f"启动 Edge 失败: {exc}, 改用默认浏览器。")
                    self.browser_proc = None
                else:
                    self.status("界面已打开 — 关闭应用窗口即退出本程序")
                    self.messages.put(("hint", "关闭应用窗口后自动结束本次会话"))
                    self.root.after(400, self.root.withdraw)
                    threading.Thread(target=self._watch_app_window,
                                     args=(self.profile_dir,), daemon=True).start()
                    self._maybe_smoke()
                    return

        self.log("改用系统默认浏览器打开界面。")
        self.status("已在浏览器中打开界面 (关闭本窗口即结束服务)")
        self.messages.put(("hint", "浏览器模式下服务持续运行, 关闭本窗口即结束服务"))
        self.btn.configure(text="停止服务并退出")
        self.bar.stop()
        self.bar.configure(mode="determinate", value=100)
        try:
            webbrowser.open(url)
        except Exception as exc:
            raise StartupError(f"打开浏览器失败, 请手动访问:\n{url}\n({exc})") from exc
        self._maybe_smoke()

    def _maybe_smoke(self) -> None:
        smoke = env_smoke_seconds()
        if smoke:
            self.log(f"[smoke] {smoke} 秒后自动结束, 用于自动化验证")
            threading.Thread(target=self._smoke_stop, args=(smoke,), daemon=True).start()

    def _smoke_stop(self, seconds: float) -> None:
        time.sleep(seconds)
        self.log("[smoke] 收尾: 关闭窗口与浏览器")
        if self.browser_proc is not None and self.browser_proc.poll() is None:
            kill_tree(self.browser_proc.pid)
        if os.name == "nt":
            needle = str(self.profile_dir).replace("/", "\\")
            ps = (
                "$ErrorActionPreference='SilentlyContinue';"
                "Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" |"
                f" Where-Object {{ $_.CommandLine -like '*{needle}*' }} |"
                " ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
            )
            try:
                subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, timeout=30,
                               creationflags=CREATE_NO_WINDOW, check=False)
            except Exception:
                pass
        self.messages.put(("close", ""))

    def _watch_app_window(self, profile: Path) -> None:
        proc = self.browser_proc
        if proc is not None:
            try:
                proc.wait()
            except Exception:
                pass
        if self._edge_running(profile):
            self.log("已接入现有浏览器实例, 等待应用窗口关闭 …")
            while self._edge_running(profile):
                time.sleep(2)
        self.messages.put(("close", ""))

    @staticmethod
    def _edge_running(profile: Path) -> bool:
        if os.name != "nt":
            return False
        needle = str(profile).replace("/", "\\")
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$p=Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" |"
            f" Where-Object {{ $_.CommandLine -like '*{needle}*' }};"
            "if($p){'yes'}else{'no'}"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=30,
                creationflags=CREATE_NO_WINDOW, check=False,
            )
            return "yes" in (out.stdout or "").lower()
        except Exception:
            return False

    # -- 收尾 -------------------------------------------------------------- #
    def _finish(self) -> None:
        if self.finished:
            return
        self.finished = True
        if not self.keep_server:
            self.status("正在结束后台服务 …")
        self.stop_server()
        self.close_log()
        try:
            self.bar.stop()
            self.root.destroy()
        except Exception:
            pass

    def on_cancel(self) -> None:
        self.messages.put(("close", ""))

    def _on_failed(self, message: str) -> None:
        self.failed = message
        self.finished = True
        try:
            self.bar.stop()
            self.bar.configure(mode="determinate", value=0)
        except Exception:
            pass
        self.status("启动失败")
        self.log("错误: " + message.replace("\n", " "))
        self.stop_server()
        self.close_log()
        try:
            from tkinter import messagebox

            messagebox.showerror(APP_TITLE, message + "\n\n详见启动日志窗口。")
        except Exception:
            print(message, file=sys.stderr)
        try:
            self.root.destroy()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    env = os.environ
    ap = argparse.ArgumentParser(
        prog="dsh_gui.py",
        description="启动 `npx @deepseek-ai/dsh web` 并显示 127.0.0.1:3080 界面的图形启动器",
    )
    ap.add_argument("--port", type=int, default=int(env.get("DSH_GUI_PORT", DEFAULT_PORT)),
                    help=f"服务端口 (默认 {DEFAULT_PORT})")
    ap.add_argument("--host", default=env.get("DSH_GUI_HOST", "127.0.0.1"),
                    help="服务地址 (默认 127.0.0.1)")
    ap.add_argument("--mode", choices=("auto", "embedded", "app", "tab"),
                    default=env.get("DSH_GUI_MODE", "auto"),
                    help="窗口模式: auto=自动(优先内嵌), embedded=内嵌窗口, "
                         "app=Edge 应用窗口, tab=浏览器标签页")
    ap.add_argument("--timeout", type=float,
                    default=float(env.get("DSH_GUI_TIMEOUT", DEFAULT_TIMEOUT)),
                    help=f"等待服务就绪的最长秒数 (默认 {int(DEFAULT_TIMEOUT)})")
    ap.add_argument("--keep-server", action="store_true",
                    default=env.get("DSH_GUI_KEEP_SERVER", "0") not in ("0", "", "false", "False"),
                    help="退出时保留后台服务 (默认关闭它)")
    ap.add_argument("--restart", action="store_true",
                    help="端口被非 DSH 程序占用时, 仍尝试在该端口启动")
    ap.add_argument("--log", default=env.get("DSH_GUI_LOG"),
                    help="把启动日志追加写入该文件")
    return ap.parse_args(argv)


def app_dir() -> Path:
    """程序所在目录: 冻结后是 exe 所在目录, 否则是脚本目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def default_log_path() -> Path:
    """默认日志路径。

    冻结后 exe 目录可能不可写 (例如放在 Program Files), 因此退回用户数据目录。
    """
    candidates = [app_dir(), Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DSH-GUI"]
    for folder in candidates:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            probe_file = folder / ".dsh-gui-write-test"
            probe_file.write_text("", encoding="utf-8")
            probe_file.unlink()
            return folder / "dsh-gui.log"
        except Exception:
            continue
    return Path(os.environ.get("TEMP", ".")) / "dsh-gui.log"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # 冻结成 exe 后没有外部解释器, 让 exe 自己充当内嵌后端探测子进程
    if INTERNAL_PROBE_FLAG in argv:
        idx = argv.index(INTERNAL_PROBE_FLAG)
        if idx + 1 < len(argv):
            try:
                return run_internal_backend_probe(argv[idx + 1])
            except BaseException:
                # 窗口模式下没有 stderr, 崩溃会毫无痕迹; 写进文件保证可诊断
                import traceback

                try:
                    Path(argv[idx + 1]).write_text(
                        "BACKEND_FAIL\n" + traceback.format_exc(), encoding="utf-8"
                    )
                except Exception:
                    pass
                return 6
        return 4

    args = parse_args(argv)
    if os.name != "nt":
        print("提示: 本程序针对 Windows 优化, 其它平台将回退到浏览器标签页模式。", file=sys.stderr)
        if args.mode == "auto":
            args.mode = "tab"

    # 没指定日志文件时给一个默认位置: 内嵌窗口模式没有可见的控制台/日志窗口,
    # 不留日志的话出问题将无从排查。
    log_file = args.log or str(default_log_path())

    launcher = Launcher(
        host=args.host, port=args.port, mode=args.mode, timeout=args.timeout,
        keep_server=args.keep_server, restart=args.restart, log_file=log_file,
    )

    try:
        launcher.mode = resolve_mode(args.mode, log=launcher.log)
        launcher.log(f"窗口模式: {launcher.mode}")

        if launcher.mode == "embedded":
            return launcher.run_embedded()
        return launcher.run_tk()
    except Exception:
        # pythonw 没有控制台, 崩溃信息会消失; 落到日志文件里便于排查
        import traceback

        text = traceback.format_exc()
        try:
            launcher.log("未捕获异常:\n" + text)
        except Exception:
            pass
        try:
            path = Path(launcher.log_file).expanduser() if launcher.log_file \
                else default_log_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n{text}")
        except Exception:
            pass
        print(text, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
