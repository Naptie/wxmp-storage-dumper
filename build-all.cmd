@echo off
REM Builds everything: native hook DLL, then the C# bridge with the DLL embedded.
REM Usage: build-all.cmd [version]   (default: read from the VERSION file)
setlocal
set ROOT=%~dp0
set VERSION=%1
if "%VERSION%"=="" set /p VERSION=<"%ROOT%VERSION"
if "%VERSION%"=="" (echo [build] ERROR: no version ^(arg or VERSION file^) & exit /b 1)

echo [build] === fetch dependencies ===
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\fetch-deps.ps1"
if errorlevel 1 exit /b 1

echo [build] === native\wmpf-hook ===
call "%ROOT%native\wmpf-hook\build.cmd" %VERSION%
if errorlevel 1 exit /b 1

echo [build] === stage hook DLL for embedding ===
if not exist "%ROOT%bridge\hook-bin" mkdir "%ROOT%bridge\hook-bin"
del /q "%ROOT%bridge\hook-bin\*.dll" 2>nul
copy /y "%ROOT%native\wmpf-hook\wmpf-hook-%VERSION%.dll" "%ROOT%bridge\hook-bin\wmpf-hook-%VERSION%.dll" >nul
if errorlevel 1 exit /b 1

echo [build] === bridge (net48) ===
dotnet build "%ROOT%bridge\wxmp-storage-dumper.csproj" -c Release -p:Version=%VERSION% --nologo
if errorlevel 1 exit /b 1

echo [build] === artifacts ===
set OUT=%ROOT%bridge\bin\Release\wxmp-storage-dumper.exe
if not exist "%OUT%" set OUT=%ROOT%bridge\bin\Release\net48\wxmp-storage-dumper.exe
if not exist "%OUT%" (echo [build] ERROR: exe not found & exit /b 1)
echo [build] ok: %OUT%
echo [build] ok: native\wmpf-hook\wmpf-hook-%VERSION%.dll
