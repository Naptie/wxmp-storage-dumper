# Provenance

This project is a GPLv2-derative work based on components and reverse
engineering from the following sources.

## WMPFDebugger

<https://github.com/evi0s/WMPFDebugger> (GPLv2)

- `native/wmpf-hook/wmpf_hook.cpp` is a C++ port of the Frida hook in
  `frida/hook.js` from WMPFDebugger. The JavaScript original remains the
  source of truth for the patch semantics (scene rewrite, WebSocket URL
  rewrite, remote-debug mode flag, CDP filter neutralization).
- `offsets/addresses.*.json` are fetched at build time (see
  `scripts/fetch-deps.ps1`, gitignored — not vendored) from WMPFDebugger's
  `frida/config/win32` offset tables. They map version-specific RVAs inside
  WeChat's WMPF runtime (`flue.dll`).
- The wire protocol codec in `bridge/DebugProtocol.cs` is reimplemented from
  the message definitions used by WMPFDebugger's bundled
  `RemoteDebugCodex.js` / `WARemoteDebugProtobuf.js` / `RemoteDebugConstants.js`
  (original reverse engineering of WeChat's private remote-debug protocol).
- The overall extraction flow (inject → enable remote debug → connect →
  CDP `Runtime.evaluate` → read `wx.getStorageSync`) follows the approach
  demonstrated by WMPFDebugger and its contributors.

## MinHook

`native/third_party/minhook` is [MinHook](https://github.com/TsudaKageyu/minhook)
(BSD 2-Clause), fetched at build time by `scripts/fetch-deps.ps1` from a pinned
commit of upstream `master` (gitignored — not vendored); see
`native/third_party/minhook/LICENSE.txt` after fetching.

## WeChat / WMPF

This project interacts with proprietary software (Tencent WeChat) for the
purpose of retrieving a user's own local data on their own machine. It does
not include any Tencent code; protocol constants were observed from WeChat's
bundled remote-debug components.
