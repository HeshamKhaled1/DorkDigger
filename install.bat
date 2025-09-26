@echo off
SET VENV_DIR=.venv_dork_monitor
echo.
echo === Dork Monitor installer (Windows) ===

REM Create virtual environment
python -m venv %VENV_DIR% || (
  echo Failed to create virtualenv. Ensure Python 3 is installed and on PATH.
  pause
  exit /b 1
)

echo Activating virtual environment...
call %VENV_DIR%\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip setuptools wheel

if exist requirements.txt (
  echo Installing dependencies from requirements.txt...
  pip install -r requirements.txt
) else (
  echo requirements.txt not found. Installing default packages...
  pip install serpapi requests beautifulsoup4 python-dotenv
)

echo.
echo Installation complete.
echo To run the tool, activate the venv:
echo   %VENV_DIR%\Scripts\activate.bat
echo Then:
echo   python dork_serpapi_monitor.py --serpapi-key YOUR_KEY --site example.com
pause
