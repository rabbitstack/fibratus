@echo off

for /f "usebackq delims=" %%i in (
    `"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`
) do set "VSINSTALLDIR=%%i\"

echo [INFO] VS install path: %VSINSTALLDIR%

call "%VSINSTALLDIR%VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1

nmake -f %1
