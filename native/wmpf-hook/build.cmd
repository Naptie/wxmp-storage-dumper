@echo off
REM Builds wmpf-hook-<version>.dll (x64 Release) with MSVC + MinHook
REM (fetched into ..\third_party by scripts\fetch-deps.ps1).
REM Usage: build.cmd [version]   (default: read from the repo-root VERSION file)
setlocal
set VERSION=%1
if "%VERSION%"=="" set /p VERSION=<"%~dp0..\..\VERSION"
if "%VERSION%"=="" (echo [build] ERROR: no version ^(arg or VERSION file^) & exit /b 1)

REM Locate vcvars64.bat: prefer vswhere (covers CI's Enterprise install),
REM then fall back to scanning VS 2022 edition folders.
set VCVARS=
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%V\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%V\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS (
  for /d %%D in ("C:\Program Files\Microsoft Visual Studio\2022\*" "C:\Program Files (x86)\Microsoft Visual Studio\2022\*") do (
    if exist "%%D\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%D\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo [build] ERROR: vcvars64.bat not found ^(install VS 2022 with C++ tools^)
  exit /b 1
)

call "%VCVARS%" >nul || exit /b 1
cd /d "%~dp0"

REM MH_STATIC keeps MinHook symbols out of our export table. The versioned
REM filename is REQUIRED: a re-injection of an already-loaded path makes
REM LoadLibraryW return the existing module without re-running DllMain.
cl /nologo /LD /O2 /MT /EHsc /GS- /W3 /utf-8 ^
  /DWMPF_HOOK_BUILD=\"%VERSION%\" /DMH_STATIC ^
  /I ..\third_party\minhook\include /I ..\third_party\minhook\src ^
  wmpf_hook.cpp ^
  ..\third_party\minhook\src\buffer.c ^
  ..\third_party\minhook\src\hook.c ^
  ..\third_party\minhook\src\trampoline.c ^
  ..\third_party\minhook\src\hde\hde64.c ^
  /Fe:wmpf-hook-%VERSION%.dll /link /NOLOGO /INCREMENTAL:NO
if errorlevel 1 exit /b 1
echo [build] ok: wmpf-hook-%VERSION%.dll
