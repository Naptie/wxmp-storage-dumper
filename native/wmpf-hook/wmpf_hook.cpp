// wmpf_hook.cpp — enables WeChat's built-in remote-debug mode for the next
// mini-program launch, so an external CDP client can read the mini program's
// local storage (wx.getStorageSync) over a loopback WebSocket.
//
// This is a GPLv2-derative C++ port of the Frida hook from WMPFDebugger
// (https://github.com/evi0s/WMPFDebugger, frida/hook.js). The JavaScript
// original is the source of truth for every patch below; see PROVENANCE.md.
//
// Contract with the injector (bridge writes this before CreateRemoteThread):
//   %TEMP%\wmpf-hook-<pid>.ini   (flat key=value; re-read on every launch)
//   %TEMP%\wmpf-hook-<pid>.log   (diagnostics)
//
// The DLL stays mapped until WeChat exits. Re-injection of the SAME path is a
// silent LoadLibraryW no-op, so every release ships under a versioned filename
// and the injector only skips injection when that exact file is already loaded.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>

#include "MinHook.h"

#ifndef WMPF_HOOK_BUILD
#define WMPF_HOOK_BUILD "dev"
#endif

namespace {

// ------------------------------------------------------------- identities ---

HMODULE g_self = nullptr;
DWORD g_pid = 0;
wchar_t g_logPath[MAX_PATH] = {0};
wchar_t g_iniPath[MAX_PATH] = {0};

// --------------------------------------------------------------- logging ---

void isoNow(char* out, size_t cap) {
    wchar_t wide[64] = {0};
    SYSTEMTIME st{};
    GetLocalTime(&st);
    swprintf_s(wide, 64, L"%04d-%02d-%02dT%02d:%02d:%02d.%03d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
               st.wSecond, st.wMilliseconds);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out, (int)cap, nullptr, nullptr);
}

void logLine(const char* fmt, ...) {
    char line[1024] = {0};
    char ts[64] = {0};
    isoNow(ts, sizeof(ts));
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE, "%s ", ts);
    if (n < 0) n = 0;
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(line + n, sizeof(line) - n, _TRUNCATE, fmt, ap);
    va_end(ap);
    size_t len = strlen(line);
    line[len] = '\n';

    HANDLE h = CreateFileW(g_logPath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)(len + 1), &written, nullptr);
    CloseHandle(h);
}

// ---------------------------------------------------------------- config ---

// Per-run configuration, re-read from the ini on EVERY whitelisted launch so
// a later run can change the listen port without re-injecting the DLL.
struct HookConfig {
    char listenUrl[128] = {0};
    uintptr_t loadStart = 0;
    uintptr_t cdpFilter = 0;
    uintptr_t castToJson = 0;  // 0 = legacy CDPFilter variant
    bool modern = false;
    // legacy: pointer-chase offsets [6]; modern: launch[3], remoteDbg[2],
    // sceneOffset, wsUrlOffset, remoteModeOffset.
    uintptr_t legacy[6] = {0};
    uintptr_t launch[3] = {0};
    uintptr_t remoteDbg[2] = {0};
    uintptr_t sceneOffset = 0;
    uintptr_t wsUrlOffset = 0;
    uintptr_t remoteModeOffset = 0;
};

bool readFileUtf8(const wchar_t* path, char* out, size_t cap) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD got = 0;
    BOOL ok = ReadFile(h, out, (DWORD)(cap - 1), &got, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    out[got] = '\0';
    return true;
}

const char* findKey(const char* ini, const char* key) {
    const char* p = ini;
    size_t klen = strlen(key);
    while (*p) {
        const char* lineEnd = strstr(p, "\n");
        size_t lineLen = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if (lineLen >= klen + 1 && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            return p + klen + 1;
        }
        if (!lineEnd) break;
        p = lineEnd + 1;
    }
    return nullptr;
}

bool parseHexOrDec(const char* s, uintptr_t* out) {
    if (!s || !*s) return false;
    uintptr_t v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        for (; *s && *s != '\r' && *s != '\n' && *s != ' ' && *s != ','; ++s) {
            int d;
            if (*s >= '0' && *s <= '9') d = *s - '0';
            else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
            else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
            else return false;
            v = v * 16 + (uintptr_t)d;
        }
        *out = v;
        return true;
    }
    for (; *s && *s != '\r' && *s != '\n' && *s != ' ' && *s != ','; ++s) {
        if (*s < '0' || *s > '9') return false;
        v = v * 10 + (uintptr_t)(*s - '0');
    }
    *out = v;
    return true;
}

bool parseList(const char* s, uintptr_t* out, int count) {
    for (int i = 0; i < count; ++i) {
        if (!parseHexOrDec(s, &out[i])) return false;
        while (*s && *s != ',') ++s;
        if (i + 1 < count) {
            if (*s != ',') return false;
            ++s;
        }
    }
    return true;
}

bool loadConfig(HookConfig* cfg) {
    char ini[4096] = {0};
    if (!readFileUtf8(g_iniPath, ini, sizeof(ini))) {
        logLine("config: cannot read %ls (err=%lu)", g_iniPath, GetLastError());
        return false;
    }

    const char* v;
    if (!(v = findKey(ini, "listenUrl"))) return false;
    _snprintf_s(cfg->listenUrl, _TRUNCATE, "%.*s",
                (int)strcspn(v, "\r\n"), v);

    if (!(v = findKey(ini, "loadStart")) || !parseHexOrDec(v, &cfg->loadStart))
        return false;
    if (!(v = findKey(ini, "cdpFilter")) || !parseHexOrDec(v, &cfg->cdpFilter))
        return false;

    cfg->castToJson = 0;
    if ((v = findKey(ini, "castToJson")) && *v && *v != '\r' && *v != '\n')
        parseHexOrDec(v, &cfg->castToJson);

    if ((v = findKey(ini, "mode")) && strncmp(v, "modern", 6) == 0) {
        cfg->modern = true;
        if (!(v = findKey(ini, "launchCfg")) || !parseList(v, cfg->launch, 3))
            return false;
        if (!(v = findKey(ini, "remoteDbg")) || !parseList(v, cfg->remoteDbg, 2))
            return false;
        if (!(v = findKey(ini, "sceneOffset")) || !parseHexOrDec(v, &cfg->sceneOffset))
            return false;
        if (!(v = findKey(ini, "wsUrlOffset")) || !parseHexOrDec(v, &cfg->wsUrlOffset))
            return false;
        if (!(v = findKey(ini, "remoteModeOffset")) ||
            !parseHexOrDec(v, &cfg->remoteModeOffset))
            return false;
    } else {
        cfg->modern = false;
        if (!(v = findKey(ini, "sceneChain")) || !parseList(v, cfg->legacy, 6))
            return false;
    }
    return true;
}

// Re-read only the listenUrl (cheap) so port changes apply without reinject.
void refreshListenUrl(HookConfig* cfg) {
    char ini[1024] = {0};
    if (!readFileUtf8(g_iniPath, ini, sizeof(ini))) return;
    const char* v = findKey(ini, "listenUrl");
    if (!v) return;
    char url[128] = {0};
    _snprintf_s(url, _TRUNCATE, "%.*s", (int)strcspn(v, "\r\n"), v);
    if (url[0] && strcmp(url, cfg->listenUrl) != 0) {
        logLine("config: listenUrl refreshed -> %s", url);
        memcpy(cfg->listenUrl, url, sizeof(cfg->listenUrl));
    }
}

// ------------------------------------------------------------ flue module ---

// The WMPF runtime lives in flue.dll since version 13331; older builds keep
// it in the main executable. Port of getMainModule() (hook.js:6-18).
HMODULE mainModuleFor(DWORD version) {
    if (version >= 13331) return GetModuleHandleW(L"flue.dll");
    return GetModuleHandleW(L"WeChatAppEx.exe");
}

DWORD detectFlueVersion() {
    const wchar_t* cmd = GetCommandLineW();
    if (!cmd) return 0;
    const wchar_t* key = wcsstr(cmd, L"--flue-runtime-dir");
    if (!key) return 0;
    const wchar_t* p = key;
    while (*p && *p != L'"' && *p != L' ' && *p != L'\t') ++p;
    wchar_t value[MAX_PATH] = {0};
    size_t n = 0;
    if (*p == L'"') {
        ++p;
        while (*p && *p != L'"' && n + 1 < MAX_PATH) value[n++] = *p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t' && n + 1 < MAX_PATH) value[n++] = *p++;
    }
    DWORD version = 0;
    const wchar_t* runStart = nullptr;
    for (size_t i = 0; i <= n; ++i) {
        bool isDigit = (i < n && value[i] >= L'0' && value[i] <= L'9');
        if (isDigit) {
            if (!runStart) runStart = &value[i];
        } else if (runStart) {
            version = wcstoul(runStart, nullptr, 10);
            runStart = nullptr;
        }
    }
    return version;
}

// -------------------------------------------------------- handleOnLoadStart --

// Scene whitelist ported verbatim from hook.js:138-144.
const int kSceneWhitelist[] = {1005, 1007, 1008, 1011, 1012, 1027, 1035,
                               1037, 1053, 1074, 1145, 1178, 1256, 1260,
                               1302, 1308};

// Writes the debug WebSocket URL into a libc++-style std::string at strP.
// Layout ported from hook.js:157-169: byte at +23 is the short-string length
// when >= 0, otherwise the string is in long representation
// { data*, size, capacity | high bit }. Only pointer and length are touched.
void writeWebSocketUrl(char* strP, const char* url) {
    size_t len = strlen(url);
    if (len > 22) {
        logLine("hook: listenUrl too long for short-string path (%zu)", len);
        return;
    }
    signed char marker = *(signed char*)(strP + 23);
    if (marker < 0) {
        // Long representation: replace data pointer + size. The new buffer is
        // process-lifetime (leaked on purpose; ~30 bytes).
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
        if (!buf) return;
        memcpy(buf, url, len + 1);
        *(char**)strP = buf;
        *(uint64_t*)(strP + 8) = (uint64_t)len;
        logLine("hook: websocket url -> %s (long repr)", url);
    } else {
        memcpy(strP, url, len);
        strP[23] = (char)len;
        logLine("hook: websocket url -> %s (short repr)", url);
    }
}

// Port of handleOnLoadStart (hook.js:77-176). a1 = index container (rcx),
// flags = arg2 (rdx). Runs inside SEH: a bad pointer skips the patch, never
// crashes WeChat.
void handleOnLoadStart(void* a1, uintptr_t flags, HookConfig* cfg) {
    __try {
        char* launch = nullptr;
        char* rdebug = nullptr;
        int* sceneP = nullptr;

        if (cfg->modern) {
            // launch = *( *( *(a1 + L0) + L1) + L2)
            char* t = *(char**)((char*)a1 + cfg->launch[0]);
            t = *(char**)(t + cfg->launch[1]);
            launch = *(char**)(t + cfg->launch[2]);
            // rdebug = *( *(launch + R0) + R1)
            t = *(char**)(launch + cfg->remoteDbg[0]);
            rdebug = *(char**)(t + cfg->remoteDbg[1]);
            sceneP = (int*)(rdebug + cfg->sceneOffset);
        } else {
            // legacy SceneOffsets chain (hook.js:87-101)
            char* t = *(char**)((char*)a1 + cfg->legacy[0]);
            t = *(char**)(t + cfg->legacy[1]);
            char* launch1 = *(char**)(t + cfg->legacy[2]);
            t = *(char**)(launch1 + cfg->legacy[3]);
            rdebug = *(char**)(t + cfg->legacy[4]);
            sceneP = (int*)(rdebug + cfg->legacy[5]);
        }

        int scene = *sceneP;
        bool whitelisted = false;
        for (int s : kSceneWhitelist) {
            if (scene == s) {
                whitelisted = true;
                break;
            }
        }
        if (!whitelisted) return;

        logLine("hook: scene %d -> 1101 (flags low byte %u -> 1)",
                scene, (unsigned)(flags & 0xff));
        *sceneP = 1101;

        if (!cfg->modern) {
            // Legacy path stops after the scene rewrite (hook.js:150-153).
            return;
        }

        refreshListenUrl(cfg);
        writeWebSocketUrl(launch + cfg->wsUrlOffset, cfg->listenUrl);

        int* modeP = (int*)(rdebug + cfg->remoteModeOffset);
        int oldMode = *modeP;
        logLine("hook: remote debug mode %d -> 1", oldMode);
        *modeP = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logLine("hook: EXCEPTION 0x%08x in handleOnLoadStart", GetExceptionCode());
    }
}

using OnLoadStart_t = void*(__fastcall*)(void*, uintptr_t);
OnLoadStart_t g_originalOnLoadStart = nullptr;
HookConfig g_cfg;

void* __fastcall detour_OnLoadStart(void* a1, uintptr_t flags) {
    // Port of hook.js:185-189 — set the debug_flag bit in arg2 if unset.
    if ((flags & 0xff) != 1) {
        flags = (flags & ~0xffULL) | 1;
    }
    handleOnLoadStart(a1, flags, &g_cfg);
    return g_originalOnLoadStart(a1, flags);
}

// -------------------------------------------------------------- CDPFilter ---

// Modern variant: replace the filter with a thin wrapper that redirects the
// two-argument conversion call (port of hook.js:27-37, Windows branch).
using CastToJson_t = void*(__fastcall*)(void*, void*);
CastToJson_t g_originalCastToJson = nullptr;
uintptr_t g_castToJsonAddr = 0;

void* __fastcall detour_CDPFilter(void* thiz, void* jsonOut, void* cborInput) {
    // Port of hook.js:33-36: call CastToJson(jsonOut, cborInput), then return
    // jsonOut (NOT CastToJson's own return value).
    __try {
        g_originalCastToJson(jsonOut, cborInput);
        return jsonOut;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logLine("hook: EXCEPTION 0x%08x in detour_CDPFilter", GetExceptionCode());
        return nullptr;
    }
}

using CdpFilter_t = void*(__fastcall*)(void*, void*, void*, void*);
CdpFilter_t g_originalCdpFilterLegacy = nullptr;

// Legacy variant: on return, if the filter status at obj+8 equals 6 (blocked),
// clear it (port of hook.js:56-74). Assumed <= 4-argument function.
void* __fastcall detour_CDPFilterLegacy(void* a0, void* a1, void* a2, void* a3) {
    void* ret = g_originalCdpFilterLegacy(a0, a1, a2, a3);
    __try {
        if (!ret) return ret;
        void* inner = *(void**)ret;
        if (!inner) return ret;
        uint32_t val = *(uint32_t*)((char*)inner + 8);
        if (val == 6) {
            *(uint32_t*)((char*)inner + 8) = 0;
            logLine("hook: CDP filter status 6 -> 0");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logLine("hook: EXCEPTION 0x%08x in CDPFilter legacy check", GetExceptionCode());
    }
    return ret;
}

// ------------------------------------------------------------------ setup ---

void setupHooks() {
    DWORD version = detectFlueVersion();
    logLine("setup: wmpf-hook %s, flue version %lu", WMPF_HOOK_BUILD, version);
    if (!version || !loadConfig(&g_cfg)) {
        logLine("setup: FAILED to load config");
        return;
    }
    logLine("setup: listenUrl=%s mode=%s", g_cfg.listenUrl,
            g_cfg.modern ? "modern" : "legacy");

    HMODULE mod = mainModuleFor(version);
    if (!mod) {
        logLine("setup: FAIL flue module not loaded");
        return;
    }
    logLine("setup: module base=0x%llx",
            (unsigned long long)(uintptr_t)mod);

    if (MH_Initialize() != MH_OK) {
        logLine("setup: FAIL MH_Initialize");
        return;
    }

    void* onLoadStart = (char*)mod + g_cfg.loadStart;
    MH_STATUS st =
        MH_CreateHook(onLoadStart, (LPVOID)&detour_OnLoadStart,
                      (LPVOID*)&g_originalOnLoadStart);
    if (st != MH_OK) {
        logLine("setup: FAIL MH_CreateHook(OnLoadStart) status=%d", st);
        return;
    }
    st = MH_EnableHook(onLoadStart);
    if (st != MH_OK) {
        logLine("setup: FAIL MH_EnableHook(OnLoadStart) status=%d", st);
        return;
    }
    logLine("setup: OnLoadStart hook installed at 0x%llx",
            (unsigned long long)(uintptr_t)onLoadStart);

    void* cdpFilter = (char*)mod + g_cfg.cdpFilter;
    if (g_cfg.castToJson) {
        g_castToJsonAddr = (uintptr_t)mod + g_cfg.castToJson;
        // Resolve the original once; the wrapper calls it directly.
        g_originalCastToJson = (CastToJson_t)g_castToJsonAddr;
        st = MH_CreateHook(cdpFilter, (LPVOID)&detour_CDPFilter, nullptr);
        if (st == MH_OK) st = MH_EnableHook(cdpFilter);
        if (st != MH_OK) {
            logLine("setup: FAIL CDPFilter (modern) status=%d", st);
            return;
        }
        logLine("setup: CDPFilter hook installed at 0x%llx (modern)",
                (unsigned long long)(uintptr_t)cdpFilter);
    } else {
        st = MH_CreateHook(cdpFilter, (LPVOID)&detour_CDPFilterLegacy,
                           (LPVOID*)&g_originalCdpFilterLegacy);
        if (st == MH_OK) st = MH_EnableHook(cdpFilter);
        if (st != MH_OK) {
            logLine("setup: FAIL CDPFilter (legacy) status=%d", st);
            return;
        }
        logLine("setup: CDPFilter hook installed at 0x%llx (legacy)",
                (unsigned long long)(uintptr_t)cdpFilter);
    }

    logLine("setup: READY — open the target mini program now");
}

DWORD WINAPI worker(LPVOID) {
    wchar_t temp[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, temp) == 0) return 1;
    swprintf_s(g_logPath, MAX_PATH, L"%swmpf-hook-%lu.log", temp, g_pid);
    swprintf_s(g_iniPath, MAX_PATH, L"%swmpf-hook-%lu.ini", temp, g_pid);
    setupHooks();
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = hModule;
        g_pid = GetCurrentProcessId();
        // DllMain does one thing only: spawn the worker. All real work
        // (log paths, config load, MinHook) happens off the loader lock.
        CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    }
    return TRUE;
}
