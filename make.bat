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

set GOTEST=go test -v -race -gcflags=all=-d=checkptr=0
set GOVET=go vet
set GOFMT=gofmt -e -s -l -w
set GOLINT=%GOBIN%\golint -set_exit_status

set LDFLAGS="-s -w -X github.com/rabbitstack/fibratus/cmd/fibratus/app.version=%VERSION% -X github.com/rabbitstack/fibratus/cmd/fibratus/app.commit=%COMMIT%"

:: In case you want to avoid CGO overhead or don't need a specific feature,
:: try tweaking these conditional compilation tags. By default, Fibratus is
:: built with filament, yara and kcap support.
if NOT DEFINED TAGS (
    set TAGS=kcap,filament,yara
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
if "%~1"=="deps" goto deps
if "%~1"=="rsrc" goto rsrc

:build
:: set PKG_CONFIG_PATH=pkg-config
go build -ldflags %LDFLAGS% -tags %TAGS% -o .\cmd\fibratus\fibratus.exe .\cmd\fibratus
goto :EOF

:test
%GOTEST% %PKGS%
goto :EOF

:lint
%GOVET%
%GOLINT% %PKGS%
goto :EOF

:fmt
%GOFMT% pkg cmd
goto :EOF

:deps
go get -v -u golang.org/x/lint/golint
goto :EOF

:rsrc
set RC_VER=%VERSION:.=,%
windres --define RC_VER=%RC_VER% --define VER=%VERSION% -i cmd\fibratus\fibratus.rc -O coff -o cmd\fibratus\fibratus.syso
goto :EOF

:pkg
set RELEASE_DIR=.\build\package\release

mkdir "%~dp0\%RELEASE_DIR%"
mkdir "%~dp0\%RELEASE_DIR%\Bin"
mkdir "%~dp0\%RELEASE_DIR%\Config"
mkdir "%~dp0\%RELEASE_DIR%\Python"

copy /y ".\cmd\fibratus\fibratus.exe" "%RELEASE_DIR%\bin"
copy /y ".\configs\fibratus.yml" "%RELEASE_DIR%\config\fibratus.yml"
xcopy /s /f /y ".\filaments" "%RELEASE_DIR%\Filaments\*"

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

:: Move Python DLLs and other dependencies to the same directory where the fibratus binary
:: is located to advise Windows on the DLL search path strategy.
move %RELEASE_DIR%\python\*.dll %RELEASE_DIR%\bin

:: Download env var plugin: https://nsis.sourceforge.io/mediawiki/images/7/7f/EnVar_plugin.zip
FOR /F "usebackq" %%A IN ('%RELEASE_DIR%\bin\fibratus.exe') DO set /a SIZE=%%~zA / 1024

makensis /DVERSION=1.0.0 /DINSTALLSIZE=%SIZE% build/package/fibratus.nsi
goto :EOF

:clean
rm cmd\fibratus\fibratus.exe
goto :EOF