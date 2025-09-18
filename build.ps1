$ErrorActionPreference = "Stop"

Write-Host "[build] Detecting Python 3.12..."
$py312 = & py -3.12 -V 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python 3.12 is required for this build path. Please install Python 3.12 x64."
    exit 1
}
$pyCmd = "py -3.12"

Write-Host "[build] Creating/validating virtual environment (3.12)..."
if (Test-Path -Path ".venv") {
    try {
        $venvVer = & .\.venv\Scripts\python -c "import sys;print(sys.version.split()[0])" 2>$null
    } catch {}
    if (-not $venvVer -or ($venvVer -notlike "3.12*")) {
        Write-Host "[build] Recreating venv with Python 3.12..."
        Remove-Item -Recurse -Force .venv
        iex "$pyCmd -m venv .venv"
    }
} else {
    iex "$pyCmd -m venv .venv"
}

Write-Host "[build] Activating virtual environment..."
& .\.venv\Scripts\Activate.ps1

Write-Host "[build] Upgrading pip and installing dependencies..."
pip install --upgrade pip
if (Test-Path -Path "requirements.txt") {
    pip install -r requirements.txt
}
pip install --upgrade pyinstaller

Write-Host "[build] Verifying tkinter availability..."
python -c "import tkinter" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "[build] tkinter missing. Re-run the Python 3.12 installer and enable 'tcl/tk and IDLE'."
    exit 2
}

$basePy = python -c "import sys;print(sys.base_prefix)"
$tclRoot = Join-Path $basePy 'tcl'
$tclA = Join-Path $tclRoot 'tcl8.6'
$tkA = Join-Path $tclRoot 'tk8.6'
$addData = @()
if (Test-Path $tclA) { $addData += "--add-data `"$tclA;tcl`"" }
if (Test-Path $tkA) { $addData += "--add-data `"$tkA;tk`"" }

$hooks = @()
if (Test-Path 'pyi_hooks\rthook_tk.py') { $hooks += "--runtime-hook `"pyi_hooks\\rthook_tk.py`"" }

Write-Host "[build] Running PyInstaller..."
python -m PyInstaller --noconfirm --clean --onefile `
  --name "p-run" `
  --windowed `
  --add-data "README.md;." `
  $addData `
  $hooks `
  --hidden-import tkinter `
  --hidden-import tkinter.filedialog `
  --hidden-import tkinter.scrolledtext `
  --hidden-import tkinter.messagebox `
  --collect-submodules tkinter `
  --collect-datas tkinter `
  main.py

Write-Host "[build] Build complete. Output in ./dist/p-run.exe"

