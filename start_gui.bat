@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
    echo Project Python environment not found. Create .venv and install requirements-agent.txt first.
    pause
    exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" -m src.gui
