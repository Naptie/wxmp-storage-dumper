# wxmp-storage-dumper — one-shot installer (target for `irm | iex`).
#
# Usage (defaults):
#   irm https://raw.githubusercontent.com/Naptie/wxmp-storage-dumper/main/scripts/install.ps1 | iex
# Usage (pass-through args):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Naptie/wxmp-storage-dumper/main/scripts/install.ps1))) --keys openId,userId

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtractorArgs
)

$ErrorActionPreference = 'Stop'

# TLS 1.2 for Windows PowerShell 5.1 on older builds; UTF-8 console output.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

$Owner = 'Naptie'
$Repo = 'wxmp-storage-dumper'

$installRoot = Join-Path $env:LOCALAPPDATA 'wxmp-storage-dumper'


$ua = 'wxmp-storage-dumper-install'
function Get-LatestTag {
    $req = [Net.HttpWebRequest][Net.WebRequest]::Create("https://github.com/$Owner/$Repo/releases/latest")
    $req.AllowAutoRedirect = $false
    $req.UserAgent = $ua
    $req.Timeout = 30000
    try { $resp = $req.GetResponse() }
    catch [Net.WebException] { $resp = $_.Exception.Response }
    if ($null -eq $resp) { throw "No release found at github.com/$Owner/$Repo/releases." }
    try {
        if ([int]$resp.StatusCode -eq 302 -or [int]$resp.StatusCode -eq 301) {
            $loc = $resp.GetResponseHeader('Location')
            if ($loc -match '/tag/(.+)$') { return $Matches[1] }
        }
        throw "GitHub responded $($resp.StatusCode) instead of a release redirect."
    }
    finally { $resp.Close() }
}
$tag = Get-LatestTag

$exeUrl = "https://github.com/$Owner/$Repo/releases/latest/download/wxmp-storage-dumper.exe"

$versionDir = Join-Path $installRoot $tag
$exePath = Join-Path $versionDir 'wxmp-storage-dumper.exe'

if (-not (Test-Path $exePath)) {
    New-Item -ItemType Directory -Force -Path $versionDir | Out-Null
    Write-Host "[install] downloading $tag ..."
    Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing -UserAgent $ua
    # Keep only the two newest versioned directories.
    Get-ChildItem $installRoot -Directory |
        Sort-Object Name -Descending |
        Select-Object -Skip 2 |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

& $exePath @ExtractorArgs
$code = $LASTEXITCODE

# Keep the window open when this one-liner owns it (Win+R / double-click):
# the exe's pause cannot fire here because our powershell is its parent, and
# a parent shell would keep the console open anyway, so never block there.
$consoleHosts = @('cmd', 'powershell', 'pwsh', 'windowsterminal', 'conhost',
    'openconsole', 'bash', 'sh', 'wsl', 'ssh', 'devenv', 'code', 'cursor')
try {
    $ppid = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
    $pname = (Get-Process -Id $ppid -ErrorAction Stop).ProcessName
}
catch { $pname = $null }
if (($consoleHosts -notcontains $pname) -and -not [Console]::IsInputRedirected) {
    Write-Host ''
    if ((Get-Culture).TwoLetterISOLanguageName -eq 'zh') {
        Write-Host '按回车键退出...'
    } else {
        Write-Host 'Press Enter to exit...'
    }
    [void](Read-Host)
}
exit $code
