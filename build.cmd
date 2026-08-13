@echo off
rem Build git-remote-cloak for the current Windows machine.
rem Requires Go 1.26 or newer and Git on PATH. Optional first argument sets
rem the embedded version; otherwise the latest reachable Git tag is used.
setlocal DisableDelayedExpansion

where go >nul 2>nul
if errorlevel 1 (
    echo Error: Go 1.26 or newer is required and `go` was not found on PATH.
    echo Install it from https://go.dev/dl/ and open a new Command Prompt.
    exit /b 1
)

set "VERSION=%~1"
if not defined VERSION (
    for /f "usebackq delims=" %%V in (`git describe --tags --abbrev^=0 2^>nul`) do if not defined VERSION set "VERSION=%%V"
)
if not defined VERSION set "VERSION=unknown"

if not exist "bin" mkdir "bin"
if errorlevel 1 (
    echo Error: could not create the bin directory.
    exit /b 1
)

rem Keep Go's build cache in the ignored output directory. This also avoids
rem relying on a writable per-user LocalAppData cache location.
set "GOCACHE=%CD%\bin\.gocache"
if not exist "%GOCACHE%" mkdir "%GOCACHE%"
if errorlevel 1 (
    echo Error: could not create the Go build cache directory.
    exit /b 1
)

echo Building git-remote-cloak %VERSION%...
go build -ldflags "-X github.com/b4ryon/git-remote-cloak/internal/version.Version=%VERSION%" -o "bin\git-remote-cloak.exe" .\cmd\git-remote-cloak
if errorlevel 1 exit /b %errorlevel%

copy /y "bin\git-remote-cloak.exe" "bin\git-cloak.exe" >nul
if errorlevel 1 (
    echo Error: could not create bin\git-cloak.exe.
    exit /b 1
)

"bin\git-cloak.exe" version
if errorlevel 1 exit /b %errorlevel%

echo.
echo Built bin\git-remote-cloak.exe and bin\git-cloak.exe.
echo Add "%CD%\bin" to PATH before using git cloak or cloak:: URLs.
