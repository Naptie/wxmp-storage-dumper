# wxmp-storage-dumper

One command to read openId and any other storage values from a WeChat mini
program on Windows — no WeChat DevTools, no `package.json`, no manual offset
hunting.

The tool injects a tiny hook (~160 KB) into WeChat's mini-program runtime
(WeChatAppEx.exe), flips on WeChat's **built-in remote-debug mode**, connects
to the mini program's debug WebSocket on loopback, and reads
`wx.getStorageSync(...)` through the standard Chrome DevTools Protocol.
Everything runs locally; nothing is uploaded.

## 使用说明

一条命令，读取微信小程序本地存储（openId 等）：

```powershell
powershell -NoProfile -c "iex (irm https://raw.githubusercontent.com/Naptie/wxmp-storage-dumper/main/scripts/install.ps1)"
```

运行后按提示在微信里打开目标小程序（若已打开，先完全关闭再重新打开）。
工具会打印 appId 和存储值；`--dump` 可列出全部键，`--json` 输出机器可读格式。

## Quick start (one line)

Press **Win+R** and paste:

```powershell
powershell -NoProfile -c "iex (irm https://raw.githubusercontent.com/Naptie/wxmp-storage-dumper/main/scripts/install.ps1)"
```

> The installer downloads a ~500 KB self-contained executable to
> `%LOCALAPPDATA%\wxmp-storage-dumper\` and runs it.

Then follow the prompt: **open the target mini program in WeChat** (if it is
already open, close it fully first — only a launch _after_ the hook was
injected enters debug mode).

## Usage

```text
wxmp-storage-dumper.exe [options]

  --keys <a,b,c>    storage keys to read (default: openId)
  --dump            dump ALL storage keys instead of --keys
  --appid <wx...>   fail unless the connected mini program has this appId
  --port <n>        local debug WebSocket port (default 9421, 0 = random)
  --timeout <sec>   how long to wait for the mini program (default 600)
  --pid <n>         target this WeChatAppEx.exe pid instead of auto-detect
  --json            machine-readable JSON output
  --verbose         log protocol details
  --selftest        verify the wire codec and exit (no WeChat needed)
  --lang <zh|en>    interface language (default: follow the OS)
  -h, --help        show help
```

Examples:

```powershell
# default: read the openId key
.\wxmp-storage-dumper.exe

# read several keys, machine-readable
.\wxmp-storage-dumper.exe --keys openId,userId,unionId --json

# dump every storage key the mini program has (capped at 300 keys / 2 KB each)
.\wxmp-storage-dumper.exe --dump

# verify you opened the right mini program
.\wxmp-storage-dumper.exe --appid wx0000000000000000
```

Example output:

```text
──────────────────────────────────────────────
Mini program storage
──────────────────────────────────────────────
appId             : wx0000000000000000
openId            : oAbCdEf...
userId            : 12345
──────────────────────────────────────────────
```

## How it works

```text
┌─────────────────────────┐   CreateRemoteThread    ┌──────────────────────────┐
│ wxmp-storage-dumper.exe │ ──── LoadLibraryW ────► │ WeChatAppEx.exe          │
│                         │                         │  └ wmpf-hook-<ver>.dll   │
│                         │   %TEMP% ini config     │     · OnLoadStart hook   │
│  · WS server :9421      │ ──────────────────────► │     · scene → debug 1101 │
│  · CDP client           │ ◄── ws://127.0.0.1 ──── │     · remote-debug = 1   │
└─────────────────────────┘      (mini program)     └──────────────────────────┘
```

1. **Discover** the WMPF browser process (`WeChatAppEx.exe` carrying
   `--flue-runtime-dir`) and parse the runtime version.
2. **Inject** the embedded hook DLL. It installs MinHook detours on
   `AppletIndexContainer::OnLoadStart` and the CDP filter, using
   version-specific offsets (53 known versions embedded, unknown versions
   fetched from [WMPFDebugger](https://github.com/evi0s/WMPFDebugger)'s table).
3. On the next mini-program launch the hook rewrites the launch scene to the
   debug scene (`1101`), points the debug WebSocket at
   `ws://127.0.0.1:<port>`, and sets remote-debug mode — the mini program
   then connects to us on its own.
4. Over CDP (`Runtime.evaluate`) we find the appservice JS context and read
   `wx.getStorageSync(...)`.

### Why do I have to open the mini program manually?

WeChat has no URL scheme that reliably opens an arbitrary mini program from
the outside, and the runtime's storage is encrypted — so the launch must
happen by hand _after_ the hook is in place. It is a one-time step per
extraction (the hook stays loaded until WeChat restarts).

## Requirements

- Windows 10/11 **x64**
- WeChat 4.x desktop, running and logged in
- No .NET install needed (targets the .NET Framework 4.8 that Windows ships)

## Build from source

```bat
:: needs VS 2022 (MSVC) + .NET SDK + network (first run)
build-all.cmd
:: → native\wmpf-hook\wmpf-hook-<ver>.dll   (version comes from the VERSION file)
:: → bridge\bin\Release\wxmp-storage-dumper.exe
```

The version is defined in one place: the `VERSION` file at the repo root.
Bump it there; `build-all.cmd`, `native\wmpf-hook\build.cmd`, the C# assembly
version, and the hook-DLL file name all read it (an explicit argument still
overrides, and CI enforces that the release tag `v*` equals `VERSION`).

Third-party build inputs are **not vendored** — `build-all.cmd` starts by
running `scripts\fetch-deps.ps1`, which downloads MinHook (pinned commit) and
the WMPFDebugger offset tables (live `main`) into gitignored folders. Re-runs
skip the downloads; run `powershell -File scripts\fetch-deps.ps1 -Update` to
refresh the tables manually.

CI: pushing a `v*` tag runs `.github/workflows/release.yml`, which builds both
artifacts, runs `--selftest`, and attaches them to a GitHub release — which is
what `install.ps1` downloads.

## Security notes

- Your openId is a **credential**. Anyone who has it can act as your account
  on the corresponding mini program. Don't share outputs carelessly.
- The tool runs entirely on your machine; the only network access is an
  optional offset-table fetch from WMPFDebugger's repository (for WeChat
  versions not embedded in the binary).
- The hook DLL stays mapped in WeChat until the app restarts. Each release
  ships under a versioned DLL name so upgrades are never silently skipped.

## Limitations

- Windows x64 only (the hook is an x64 MinHook port).
- Needs a matching offset table for your WMPF version; if the table is
  missing and upstream hasn't published one yet, the tool will say so.
- The legacy (pre-modern) hook path and the CDP-filter fallback are ported
  but only exercised on the configurations present in the offset table of
  your WeChat version — please report crashes with your WeChat version.

## License

[GPL-2.0](LICENSE) (derivative of
[WMPFDebugger](https://github.com/evi0s/WMPFDebugger)'s GPLv2 hook).
See [PROVENANCE.md](PROVENANCE.md) for full credits; MinHook is BSD-2-Clause.
