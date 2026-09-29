@echo off
rem ============================================================
rem  重新打包 DSH Web GUI
rem  产物: dist\DSH Web GUI.exe  (单文件, 无控制台窗口)
rem ============================================================
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if not %errorlevel%==0 (
    echo [错误] 没有找到 python, 请先安装 Python 3.8+ 并加入 PATH。
    pause
    exit /b 1
)

echo 正在检查 PyInstaller ...
python -m PyInstaller --version >nul 2>nul
if not %errorlevel%==0 (
    echo 未安装 PyInstaller, 正在安装 ...
    python -m pip install pyinstaller
    if not %errorlevel%==0 (
        echo [错误] 安装 PyInstaller 失败。
        pause
        exit /b 1
    )
)

echo.
echo 正在打包 (首次或改依赖后约需 1-3 分钟) ...
python -m PyInstaller --noconfirm --clean dsh_gui.spec
if not %errorlevel%==0 (
    echo.
    echo [错误] 打包失败, 见上方输出。
    pause
    exit /b 1
)

echo.
echo 打包完成:
dir /b "dist\DSH Web GUI.exe"
echo 位置: %~dp0dist\DSH Web GUI.exe
echo.
pause
