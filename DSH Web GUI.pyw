#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DSH Web GUI 双击入口 (无控制台窗口)。

Windows 上 .pyw 由 pythonw.exe 执行, 不会弹出黑色控制台.
如果你更习惯批处理, 用同目录的「启动 DSH Web GUI.bat」即可.
"""

import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

LOG = HERE / "dsh-gui.log"   # 兜底: 窗口模式日志文件; --log 可另行指定

if __name__ == "__main__":
    try:
        import dsh_gui

        sys.exit(dsh_gui.main(["--log", str(LOG), *sys.argv[1:]]))
    except SystemExit:
        raise
    except BaseException:
        text = traceback.format_exc()
        try:
            with open(HERE / "dsh-gui-crash.log", "a", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except Exception:
            pass
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                None, f"启动失败:\n\n{text[-800:]}", "DSH Web GUI", 0x10
            )
        except Exception:
            pass
        sys.exit(1)
