# fetch-deps.ps1 — downloads the build dependencies that are gitignored:
#
#   native/third_party/minhook  <- TsudaKageyu/minhook @ pinned commit
#                                  (compiled into our DLL, so pinned; the
#                                  bounds-checked HDE + MSVC fixes live on
#                                  master, tag v1.3.3 does not build standalone)
#   offsets/                    <- evi0s/WMPFDebugger frida/config/win32
#                                  tables from branch main (data; follows
#                                  upstream, same trust as the runtime fetch)
#
# Invoked automatically by build-all.cmd (and therefore by CI). Re-runs skip
# downloads when the dependencies are already present; use -Update to force a
# refresh (e.g. to pick up newly adapted WMPF versions).

param([switch]$Update)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root           = Split-Path -Parent $PSScriptRoot
$MinHookRef     = '8af6b4acae5a9388fd742b56fa79ece89d96f823'
$MinHookDir     = Join-Path $Root 'native\third_party\minhook'
$MinHookMarker  = Join-Path $MinHookDir '.dep-version'
$OffsetsDir     = Join-Path $Root 'offsets'
$OffsetsMarker  = Join-Path $OffsetsDir '.dep-source'
$Tmp            = Join-Path $env:TEMP ('wxmp-deps-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))

function Get-MinHook {
    $cached = (Test-Path (Join-Path $MinHookDir 'include\MinHook.h')) -and
              (Test-Path $MinHookMarker) -and
              ((Get-Content $MinHookMarker -Raw).Trim() -eq $MinHookRef)
    if ($cached -and -not $Update) {
        Write-Host "[fetch] minhook $($MinHookRef.Substring(0, 12)) (cached)"
        return
    }
    Write-Host "[fetch] minhook $($MinHookRef.Substring(0, 12)) ..."
    New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
    $zip = Join-Path $Tmp 'minhook.zip'
    Invoke-WebRequest -UseBasicParsing `
        -Uri "https://github.com/TsudaKageyu/minhook/archive/$MinHookRef.zip" `
        -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath (Join-Path $Tmp 'mh') -Force
    $top = Get-ChildItem (Join-Path $Tmp 'mh') | Select-Object -First 1
    if ($null -eq $top) { throw 'minhook archive was empty' }
    if (Test-Path $MinHookDir) { Remove-Item -Recurse -Force $MinHookDir }
    New-Item -ItemType Directory -Force -Path (Split-Path $MinHookDir) | Out-Null
    Move-Item $top.FullName $MinHookDir
    # Drop in our MSVC shim: upstream's src/hde/hde64.h includes "pstdint.h",
    # which only MinGW ships; keep the fetched tree byte-for-byte as published.
    Copy-Item (Join-Path $Root 'native\patches\minhook-pstdint.h') `
              (Join-Path $MinHookDir 'src\hde\pstdint.h') -Force
    Set-Content -Path $MinHookMarker -Value $MinHookRef -NoNewline -Encoding Ascii
    Write-Host "[fetch] minhook ready"
}

function Get-Offsets {
    $count = @(Get-ChildItem -Path $OffsetsDir -Filter 'addresses.*.json' `
                 -ErrorAction SilentlyContinue).Count
    if ($count -ge 40 -and -not $Update) {
        Write-Host "[fetch] offsets ($count tables, cached)"
        return
    }
    Write-Host '[fetch] offsets from evi0s/WMPFDebugger ...'
    New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
    $tar = Join-Path $Tmp 'wmpf.tar.gz'
    $branch = $null
    foreach ($ref in @('main', 'master')) {
        try {
            Invoke-WebRequest -UseBasicParsing `
                -Uri "https://codeload.github.com/evi0s/WMPFDebugger/tar.gz/refs/heads/$ref" `
                -OutFile $tar
            $branch = $ref
            break
        } catch { }
    }
    if ($null -eq $branch) { throw 'failed to download WMPFDebugger offset tables' }
    $ext = Join-Path $Tmp 'wmpf'
    New-Item -ItemType Directory -Force -Path $ext | Out-Null
    & tar.exe -xzf $tar -C $ext
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed (code $LASTEXITCODE)" }
    $src = Get-ChildItem -Path $ext -Recurse -Directory -Filter 'win32' |
           Where-Object { $_.FullName -match '\\frida\\config\\win32$' } |
           Select-Object -First 1
    if ($null -eq $src) { throw 'frida/config/win32 not found in archive' }
    New-Item -ItemType Directory -Force -Path $OffsetsDir | Out-Null
    Copy-Item (Join-Path $src.FullName 'addresses.*.json') $OffsetsDir -Force
    $count = @(Get-ChildItem $OffsetsDir -Filter 'addresses.*.json').Count
    if ($count -lt 40) { throw "only $count offset tables extracted (expected 40+)" }
    Set-Content -Path $OffsetsMarker -Encoding Ascii `
        -Value "WMPFDebugger@$branch ($(Get-Date -Format yyyy-MM-dd))"
    Write-Host "[fetch] offsets: $count tables from '$branch'"
}

try {
    Get-MinHook
    Get-Offsets
    exit 0
}
finally {
    if (Test-Path $Tmp) {
        Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
    }
}
