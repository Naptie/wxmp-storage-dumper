// L10n.cs — localized user-facing strings (instructions + results only).
//
// Technical log lines ([discover], [inject], [ws], selftest, ...) intentionally
// stay English. Locale resolution: --lang flag, else the OS UI culture.

using System.Globalization;

namespace WxmpStorageDumper
{
    internal static class L10n
    {
        /// <summary>True when user-facing text should be Chinese.</summary>
        public static bool Zh =
            CultureInfo.CurrentUICulture.Name
                .StartsWith("zh", System.StringComparison.OrdinalIgnoreCase);

        /// <summary>Apply an explicit --lang override (zh* / en*).</summary>
        public static bool TrySetLang(string lang)
        {
            if (lang == null) return false;
            if (lang.StartsWith("zh", System.StringComparison.OrdinalIgnoreCase))
            {
                Zh = true;
                return true;
            }
            if (lang.StartsWith("en", System.StringComparison.OrdinalIgnoreCase))
            {
                Zh = false;
                return true;
            }
            return false;
        }

        /// <summary>Pick zh or en depending on the active locale.</summary>
        public static string T(string en, string zh) => Zh ? zh : en;

        public static string HelpText()
        {
            if (!Zh)
            {
                return
@"wxmp-storage-dumper — read a mini program's local storage (openId etc.) on Windows

Usage:
  wxmp-storage-dumper.exe [options]

Options:
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
  -h, --help        show this help

Steps it performs for you:
  1. finds the running WeChat mini-program runtime (WeChatAppEx.exe)
  2. injects a small hook that enables WeChat's built-in remote debug
  3. waits for the mini program to connect and reads storage via CDP

One manual step is unavoidable: when prompted, open the mini program in
WeChat (close it first if already open — only a launch after the hook was
injected enters debug mode).

Windows x64 only. Requires WeChat 4.x running and logged in.";
            }
            return
@"wxmp-storage-dumper — 在 Windows 上读取小程序本地存储（openId 等）

用法:
  wxmp-storage-dumper.exe [选项]

选项:
  --keys <a,b,c>    要读取的存储键（默认: openId）
  --dump            导出全部存储键，代替 --keys
  --appid <wx...>   连接的小程序 appId 不符时失败退出
  --port <n>        本地调试 WebSocket 端口（默认 9421，0 = 随机）
  --timeout <sec>   等待小程序连接的时长（默认 600 秒）
  --pid <n>         指定目标 WeChatAppEx.exe 进程号，跳过自动检测
  --json            输出机器可读的 JSON
  --verbose         记录协议细节日志
  --selftest        仅校验编解码后退出（无需微信）
  --lang <zh|en>    界面语言（默认: 跟随系统）
  -h, --help        显示此帮助

它会自动完成:
  1. 查找正在运行的小程序运行时进程（WeChatAppEx.exe）
  2. 注入小型钩子，开启微信自带的远程调试
  3. 等待小程序连接并通过 CDP 读取存储

有一步必须手动完成: 按提示在微信中打开该小程序（若已打开，请先完全
关闭再打开——只有钩子注入之后启动的进程才会进入调试模式）。

仅支持 Windows x64。需要运行并已登录微信 4.x。";
        }
    }
}
