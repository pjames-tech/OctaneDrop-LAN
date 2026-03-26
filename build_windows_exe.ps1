$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
  python -m pip install --upgrade pip
  python -m pip install -r requirements-build.txt
  python -m PyInstaller --noconfirm --clean orange_drop_lan.spec
  Write-Host "Built dist/OctaneDropLAN.exe"
}
finally {
  Pop-Location
}
