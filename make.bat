:: Copyright 2019-2020 by Nedim Sabic Sabic
:: https://www.fibratus.io
:: All Rights Reserved.
::
:: Licensed under the Apache License, Version 2.0 (the "License"); you may
:: not use this file except in compliance with the License. You may obtain
:: a copy of the License at
::
:: http://www.apache.org/licenses/LICENSE-2.0

@echo off
SetLocal EnableDelayedExpansion

set PYTHON_VER=3.7.9
set PYTHON_URL=https://www.python.org/ftp/python/%PYTHON_VER%/python-%PYTHON_VER%-embed-amd64.zip

set GOBIN=%USERPROFILE%\go\bin

set GOTEST=go test -timeout=10m -v -gcflags=all=-d=checkptr=0
set GOFMT=gofmt -e -s -l -w
set GOLINT=%GOBIN%\golangci-lint

FOR /F "tokens=* USEBACKQ" %%F IN (`powershell -Command get-date -format "{dd-MM-yyyy.HH:mm:ss}"`) DO (
    SET BUILD_DATE=%%F
)
set LDFLAGS="-s -w -X github.com/rabbitstack/fibratus/cmd/fibratus/app.version=%VERSION% -X github.com/rabbitstack/fibratus/cmd/fibratus/app.commit=%COMMIT% -X github.com/rabbitstack/fibratus/cmd/fibratus/app.date=%BUILD_DATE%"

:: In case you want to avoid CGO overhead or don't need a specific feature, try tweaking the following compilation tags:
::
:: kcap: enables capture support
:: filament: enables running filaments and thus interacting with the CPython interpreter
:: yara: enables YARA scanner via cgo bindings
if NOT DEFINED TAGS (
    set TAGS=""
)

set PKGS=
:: Get the list of packages that we'll use to run tests/linter
for /f %%p in ('go list .\...') do call set "PKGS=%%PKGS%% %%p"


if "%~1"=="build" goto build
if "%~1"=="test" goto test
if "%~1"=="lint" goto lint
if "%~1"=="fmt" goto fmt
if "%~1"=="clean" goto clean
if "%~1"=="pkg" goto pkg
if "%~1"=="pkg-slim" goto pkg-slim
if "%~1"=="install" goto install
if "%~1"=="deps" goto deps
if "%~1"=="rsrc" goto rsrc
if "%~1"=="mc" goto mc

:build
:: set PKG_CONFIG_PATH=pkg-config
go build -ldflags %LDFLAGS% -tags %TAGS% -o .\cmd\fibratus\fibratus.exe .\cmd\fibratus
go build -ldflags %LDFLAGS% -o .\cmd\systray\fibratus-systray.exe .\cmd\systray
if errorlevel 1 goto fail
goto :EOF

:test
%GOTEST% -tags %TAGS% %PKGS%
if errorlevel 1 goto fail
goto :EOF

:lint
%GOLINT% run --timeout 10m
if errorlevel 1 goto fail
goto :EOF

:fmt
%GOFMT% pkg cmd internal
goto :EOF

:deps
go get -v -u github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2
goto :EOF

:rsrc
set RC_VER=%VERSION:.=,%
windres --define RC_VER=%RC_VER% --define VER=%VERSION% -i cmd\fibratus\fibratus.rc -O coff -o cmd\fibratus\fibratus.syso
windres --define RC_VER=%RC_VER% --define VER=%VERSION% -i cmd\systray\fibratus-systray.rc -O coff -o cmd\systray\fibratus-systray.syso
if errorlevel 1 goto fail
goto :EOF

:mc
windmc -r pkg/outputs/eventlog/mc pkg/outputs/eventlog/mc/fibratus.mc
windres -O coff -r -fo pkg/outputs/eventlog/mc/fibratus.res pkg/outputs/eventlog/mc/fibratus.rc
:: Link the resulting resource object
gcc pkg/outputs/eventlog/mc/fibratus.res -o pkg/outputs/eventlog/mc/fibratus.dll -s -shared "-Wl,--subsystem,windows"
if errorlevel 1 goto fail
goto :EOF

:pkg
set RELEASE_DIR=.\build\msi\fibratus-%VERSION%

:: Create the directory structure
mkdir "%~dp0\%RELEASE_DIR%"
mkdir "%~dp0\%RELEASE_DIR%\Bin"
mkdir "%~dp0\%RELEASE_DIR%\Config"
mkdir "%~dp0\%RELEASE_DIR%\Rules"
mkdir "%~dp0\%RELEASE_DIR%\Python"
mkdir "%~dp0\%RELEASE_DIR%\Filaments"

echo Copying artifacts...
:: Copy artifacts
copy /y ".\cmd\fibratus\fibratus.exe" "%RELEASE_DIR%\Bin"
copy /y ".\cmd\systray\fibratus-systray.exe" "%RELEASE_DIR%\Bin"
copy /y ".\configs\fibratus.yml" "%RELEASE_DIR%\Config\fibratus.yml"
copy /y ".\pkg\outputs\eventlog\mc\fibratus.dll" "%RELEASE_DIR%\fibratus.dll"

robocopy ".\filaments" "%RELEASE_DIR%\Filaments" /E /S /XF *.md /XD __pycache__ .idea
robocopy ".\rules" "%RELEASE_DIR%\Rules" /E /S /XF *.md *.png

:: Download the embedded Python distribution
echo Downloading Python %PYTHON_VER%...
powershell -Command "Invoke-WebRequest %PYTHON_URL% -OutFile %RELEASE_DIR%\python.zip"

echo Extracting Python distribution...
powershell -Command "Expand-Archive %RELEASE_DIR%\python.zip -DestinationPath %RELEASE_DIR%\python"

:: Bring in the pip
:: https://stackoverflow.com/questions/42666121/pip-with-embedded-python
powershell -Command "(Get-Content -path %RELEASE_DIR%\python\python*._pth -Raw) -replace '#import','import' | Set-Content -Path %RELEASE_DIR%\python\python*._pth"
echo Downloading get-pip.py...
powershell -Command "Invoke-WebRequest https://bootstrap.pypa.io/get-pip.py -OutFile %RELEASE_DIR%\get-pip.py"
%RELEASE_DIR%\python\python.exe %RELEASE_DIR%\get-pip.py

del %RELEASE_DIR%\get-pip.py
del %RELEASE_DIR%\python.zip

:: Move Python DLLs and other dependencies to the same directory
:: where the fibratus binary is located to advise Windows on the
:: DLL search path strategy.
move %RELEASE_DIR%\python\*.dll %RELEASE_DIR%\bin

:: Rename libcrypto-1_1.dll to libcrypto-3-x64.dll
ren "%RELEASE_DIR%\bin\libcrypto-1_1.dll" "libcrypto-3-x64.dll"
:: Copy Debug Help DLL
copy %SystemRoot%\System32\dbghelp.dll "%RELEASE_DIR%\Bin"

echo Building MSI package...
pushd .
cd build/msi
wix extension add WixToolset.UI.wixext || exit /b
wix extension add WixToolset.Util.wixext || exit /b
wix build -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -b dir=fibratus-%VERSION% fibratus.wxs -arch x64 -d VERSION=%VERSION% -o fibratus-%VERSION%-amd64.msi || exit /b
popd
echo fibratus-%VERSION%-amd64.msi MSI package built successfully

if errorlevel 1 goto fail

goto :EOF

:pkg-slim
set RELEASE_DIR=.\build\msi\fibratus-%VERSION%-slim

:: Create the dir structure
mkdir "%~dp0\%RELEASE_DIR%"
mkdir "%~dp0\%RELEASE_DIR%\Bin"
mkdir "%~dp0\%RELEASE_DIR%\Config"
mkdir "%~dp0\%RELEASE_DIR%\Rules"

echo Copying artifacts...
:: Copy artifacts
copy /y ".\cmd\fibratus\fibratus.exe" "%RELEASE_DIR%\Bin"
copy /y ".\cmd\systray\fibratus-systray.exe" "%RELEASE_DIR%\Bin"
copy /y ".\configs\fibratus.yml" "%RELEASE_DIR%\Config\fibratus.yml"
copy /y ".\pkg\outputs\eventlog\mc\fibratus.dll" "%RELEASE_DIR%\fibratus.dll"

robocopy ".\rules" "%RELEASE_DIR%\Rules" /E /S /XF *.md *.png

:: Copy Debug Help DLL
copy %SystemRoot%\System32\dbghelp.dll "%RELEASE_DIR%\Bin"

echo Building MSI package...
pushd .
cd build/msi
wix extension add WixToolset.UI.wixext || exit /b
wix extension add WixToolset.Util.wixext || exit /b
wix build -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -b dir=fibratus-%VERSION%-slim fibratus.wxs -arch x64 -d VERSION=%VERSION% -o fibratus-%VERSION%-slim-amd64.msi || exit /b
popd
echo fibratus-%VERSION%-slim-amd64.msi MSI package built successfully

if errorlevel 1 goto fail

goto :EOF

:clean
del cmd\fibratus\fibratus.exe
del cmd\systray\fibratus-systray.exe
goto :EOF

:: Install the dev MSI. This target executes
:: the msiexec in the background, and waits
:: for process completion. Once the command
:: finishes, the install log is dumped to
:: help diagnosing installer failures
:install
echo Installing Fibratus...
start /b /wait msiexec /i fibratus-0.0.0-amd64.msi /qn /l*! install.log
timeout 2 > NUL
type install.log
goto :EOF

:fail
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
