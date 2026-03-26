@echo off
setlocal
cd /d %~dp0
python -m pip install --upgrade pip
if errorlevel 1 exit /b %errorlevel%
python -m pip install -r requirements-build.txt
if errorlevel 1 exit /b %errorlevel%
python -m PyInstaller --noconfirm --clean orange_drop_lan.spec
if errorlevel 1 exit /b %errorlevel%
echo Built dist\OctaneDropLAN.exe
