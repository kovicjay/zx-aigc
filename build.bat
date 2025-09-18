@echo off
setlocal

rem Check Python launcher
py -V >nul 2>&1
if errorlevel 1 goto PY_NOT_FOUND

rem Require Python 3.12 (best compatibility with PyInstaller + tkinter)
for /f "tokens=*" %%v in ('py -3.12 -V 2^>nul') do set PY312=%%v
if not defined PY312 goto PY312_INSTALL
set "PY_CMD=py -3.12"

rem Create venv if missing, or recreate if not 3.12
if not exist .venv goto MAKE_VENV
for /f "usebackq tokens=*" %%v in (`.venv\Scripts\python -c "import sys;print(sys.version.split()[0])" 2^>nul`) do set VENVVER=%%v
echo [build] Existing venv Python: %VENVVER%
echo %VENVVER% | findstr /C:"3.12" >nul
if %errorlevel%==0 goto HAVE_VENV
echo [build] Recreating venv with Python 3.12...
rmdir /s /q .venv
:MAKE_VENV
echo [build] Creating virtual environment (3.12)...
%PY_CMD% -m venv .venv
:HAVE_VENV

call .venv\Scripts\activate.bat

python -m pip install --upgrade pip
if exist requirements.txt goto HAVE_REQ
goto SKIP_REQ
:HAVE_REQ
pip install -r requirements.txt
:SKIP_REQ
python -m pip install --upgrade pyinstaller

rem Verify tkinter availability
python -c "import tkinter" >nul 2>&1
if errorlevel 1 goto NO_TK

for /f "usebackq tokens=*" %%v in (`python -c "import sys,os;print(sys.base_prefix)"`) do set BASEPY=%%v
set TCLROOT=%BASEPY%\tcl
set TCLA=%TCLROOT%\tcl8.6
set TCKA=%TCLROOT%\tk8.6
set ADDDATA=
if exist "%TCLA%" set ADDDATA=--add-data "%TCLA%;tcl"
if exist "%TCKA%" set ADDDATA=%ADDDATA% --add-data "%TCKA%;tk"

rem Include PyInstaller runtime hook for Tk
set HOOKS=
if exist "pyi_hooks\rthook_tk.py" set HOOKS=--runtime-hook "pyi_hooks\rthook_tk.py"

python -m PyInstaller --noconfirm --clean --onefile --name "p-run" --windowed --add-data "README.md;." %ADDDATA% %HOOKS% --hidden-import tkinter --hidden-import tkinter.filedialog --hidden-import tkinter.scrolledtext --hidden-import tkinter.messagebox --collect-submodules tkinter --collect-datas tkinter main.py
if errorlevel 1 goto BUILD_FAIL

echo [build] Build complete. See dist\p-run.exe
exit /b 0

:PY_NOT_FOUND
echo Python launcher (py) not found. Please install Python 3.10+.
exit /b 1

:PY312_INSTALL
echo [build] Python 3.12 not found. Attempting automatic install (per-user)...
set "PY_VER=3.12.6"
set "PY_MAJMIN=3.12"
set "PY_URL=https://www.python.org/ftp/python/%PY_VER%/python-%PY_VER%-amd64.exe"
set "PY_EXE=%TEMP%\python-%PY_VER%-amd64.exe"

powershell -NoProfile -ExecutionPolicy Bypass -Command "try{ Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%PY_EXE%' -UseBasicParsing }catch{ exit 1 }" 
if errorlevel 1 (
  echo [build] Failed to download Python %PY_VER%. Please install it manually from https://www.python.org.
  exit /b 1
)

"%PY_EXE%" /quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_pip=1 Include_tcltk=1 SimpleInstall=1 Shortcuts=0 Include_test=0
if errorlevel 1 (
  echo [build] Python installer failed. Please install Python %PY_VER% manually.
  exit /b 1
)

del /q "%PY_EXE%" >nul 2>&1

rem Re-check availability
for /f "tokens=*" %%v in ('py -3.12 -V 2^>nul') do set PY312=%%v
if not defined PY312 (
  echo [build] Python 3.12 still not available after install. Aborting.
  exit /b 1
)
set "PY_CMD=py -3.12"
goto MAKE_VENV

:BUILD_FAIL
echo Build failed.
exit /b 1

:NO_TK
echo [build] tkinter missing. Re-run the Python 3.13 installer and enable "tcl/tk and IDLE" feature, then rebuild.
exit /b 2
