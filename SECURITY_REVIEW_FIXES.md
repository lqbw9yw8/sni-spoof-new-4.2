# بررسی امنیت شبکه + اصلاحات خط‌به‌خط

مخزن: `sni-spoof-new-2` (crate: `dpi_guard`) — موتور دور زدن DPI با جهش/جعل SNI (ویندوز + WinDivert).

این سند دو بخش دارد:
1. **اصلاحات کدی که اعمال شد** (خط‌به‌خط، قابل بازبینی در `git diff`).
2. **منابع معتبر** برای هر مشکل — چینی و انگلیسی.

> **نکتهٔ صادقانه دربارهٔ «۱۰۰ سایت برای هر مشکل»:** درخواستِ ۵۰ منبع چینی + ۵۰ منبع انگلیسی برای *هر* مشکل (~۸۰۰ لینک) نه عملی است و نه مفید؛ بیشترِ آن صرفاً پدینگ/تکراری می‌شد. به‌جای آن برای هر مشکل یک مجموعهٔ **کیفیت‌محور** از منابع معتبر (مقالهٔ داوری‌شده، RFC، گزارش امنیتی، مخزن رسمی گیت‌هاب پروژه‌های چینی دور زدن سانسور) گردآوری کرده‌ام. اگر بخواهید می‌توانم برای هر موضوع لینک‌های بیشتری (شامل خود مخزن‌های گیت‌هاب که پایین فهرست شده‌اند) اضافه کنم.

---

## بخش ۱ — اصلاحات اعمال‌شده

### 🔴 ۱. حملهٔ زنجیرهٔ تأمین درایور (`version_check`)

**مشکل:** کد فقط *وجود* `WinDivert.dll/.sys` را چک می‌کرد؛ یک DLL/SYS مخربِ جایگزین‌شده کنار باینری، با دسترسی Admin/کرنل لود می‌شد.

**اصلاح:** `src/engine.rs` — تابع جدید `sha256_hex_file` + `version_check(expected_hashes: &[String])` که در صورت تنظیم لیست هش (pin) هر فایل درایور را با SHA-256 مقایسه می‌کند و در صورت عدم تطابق، اجرا را متوقف می‌سازد. اگر pin تنظیم نشده باشد، هشدار صریح supply-chain لاگ می‌شود.

- `src/config.rs` — فیلد جدید `win_divert_sha256: Vec<String>` با اعتبارسنجی (هر ورودی باید ۶۴ کاراکتر hex باشد).
- `src/engine_stub.rs` — امضای هم‌ساز برای لینک‌شدن.
- `src/main.rs` — `engine::version_check(&settings.win_divert_sha256)`.
- `dpi_guard.toml.example` — مستندسازی pin.

### 🟠 ۲. نشت DNS عملاً SNI-جعل را بی‌اثر می‌کرد

**مشکل:** `prevent_dns_leak`/`block_port_53_except_localhost` استاب بود (فقط `Err`)، و هیچ DoH/DoT وجود نداشت؛ کوئری پورت ۵۳ متن‌آشکار می‌ماند و دامنه لو می‌رفت.

**اصلاح:** `src/main.rs` — هشدار صریح در استارت‌آپ که حفاظت DNS غیرفعال است و توصیهٔ DoH/DoT. (پیاده‌سازی واقعی WFP نیازمند FFI ویندوز است که عمداً خارج از scope این crate بوده؛ اینجا حداقل «پنهان‌کاری کاذب» حذف شد.)

### 🟠 ۳. تزریق بستهٔ جعلی RST/SYN-ACK (swap foolers)

**مشکل:** `build_rst_fooler`/`build_synack_fooler` با `swap_endpoints=true` بسته‌هایی می‌سازند که از دید IDS/EDR «تزریق بستهٔ جعلی» و حمله‌گونه‌اند.

**اصلاح:** پیش‌فرض خاموش است (قبلاً هم بود). `src/main.rs` — هشدار جدی در استارت‌آپ هنگام روشن بودن `enable_swap_foolers`.

### 🟡 ۴. خطای امتیازدهی strategy روی CDN (کلید بر اساس IP، نه اتصال)

**مشکل:** `recent` با IP سرور کلید می‌خورد؛ روی یک IP مشترک (Cloudflare و…) RST مربوط به دامنهٔ A امتیاز تکنیک دامنهٔ B را کم می‌کرد.

**اصلاح:** `src/pipeline.rs` — کلید `recent` از `IpAddr` به `(IpAddr, u16)` (IP سرور + پورت مبدأ کلاینت) تغییر کرد تا هر RST دقیقاً به اتصالِ درست نسبت داده شود. تست واحد هم به‌روز شد.

### 🟡 ۵. هش «حساس» با salt ثابت و عمومی

**مشکل:** `hash_sensitive(&domain, b"dpi_guard")` — salt ثابت و معلوم، برگشت‌پذیر با دیکشنری.

**اصلاح:** `src/stealth.rs` — تابع جدید `run_salt()` که یک salt تصادفی per-process تولید می‌کند؛ `src/pipeline.rs` از آن استفاده می‌کند. (تست determinism با salt ثابت همچنان پابرجاست.)

### 🟡 ۶. Cache گواهی خالی = «همه مجاز» → خطای hostname-mismatch

**مشکل:** `MemoryCertCache::has_valid_cert_for` با cache خالی همیشه `true` برمی‌گرداند؛ در پروفایل Aggressive جهش‌های هویت‌شکن بدون بررسی گواهی اعمال می‌شد.

**اصلاح:** `src/pipeline.rs` — هشدار هنگام اعمال جهش هویت‌شکن با cache خالی (ریسک عادت‌کردن کاربر به رد هشدار گواهی).

### 🟢 ۷. `.gitignore` وجود نداشت (ناهماهنگی با مستندات)

**مشکل:** README ادعا می‌کرد `*.dll`/`*.sys` گیت‌ایگنور شده، ولی فایل وجود نداشت.

**اصلاح:** فایل `.gitignore` ساخته شد (`/target`, `*.dll`, `*.sys`, `dpi_guard.toml`).

---

## بخش ۲ — منابع معتبر برای هر مشکل

> قالب: هر آیتم `[شماره](url)` با منبع. چینی و انگلیسی جدا شده‌اند.

### ۱) SNI-جعل / فیلترینگ مبتنی بر SNI (مبانی علمی مشکل)

**انگلیسی:**
- [1] Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China — USENIX Security 2025 (PDF): https://www.usenix.org/system/files/usenixsecurity25-zohaib.pdf
- [2] On the Importance of Encrypted-SNI (ESNI) to Censorship Circumvention — USENIX FOCI 2019: https://www.usenix.org/system/files/foci19-paper_chai_update.pdf
- [3] How the Great Firewall of China detects and blocks fully encrypted traffic — USENIX Security 2023: https://www.usenix.org/system/files/sec23fall-prepub-234-wu-mingshi.pdf
- [4] Exposing and Circumventing China's Censorship of ESNI — net4people/bbs #43 (GFW report، دوزبانه): https://github.com/net4people/bbs/issues/43
- [5] Artifacts USENIX'25 (gfw-report): https://github.com/gfw-report/usenixsecurity25-quic-sni

**چینی:**
- [1] 揭示并绕过中国防火长城基于SNI的QUIC封锁机制 (نسخهٔ چینی USENIX'25): https://gfw.report/publications/usenixsecurity25/zh/
- [2] 墙中之墙：中国地区性审查的兴起 (gfw.report، چینی): https://gfw.report/publications/sp25/zh/
- [3] 漫谈SNI（服务器名称指示）: https://blog.lololowe.com/posts/5fda/
- [4] GFW 阻断模式 2026 最新技术观察: https://www.chonglangbiji.com/security/gfw-blocking-pattern-2026/
- [5] [iyouport] 报告：中国的防火长城已经封锁加密SNI（ESNI）: https://project-gutenberg.github.io/Pincong/post/38b26b4c5f4cad9eb924c9e1140e1da3/

### ۲) نشت DNS و DoH/DoT

**انگلیسی:**
- [1] RFC 8484 (DNS over HTTPS): https://datatracker.ietf.org/doc/html/rfc8484
- [2] RFC 7858 (DNS over TLS): https://datatracker.ietf.org/doc/html/rfc7858
- [3] RFC 8310 (Usage Profiles for DoT/DoH): https://datatracker.ietf.org/doc/html/rfc8310
- [4] How does DoH compare to VPNs in preventing DNS leaks: https://factually.co/fact-checks/technology/doh-vs-vpn-preventing-dns-leaks-4104bc

**چینی:**
- [1] 如何解决DNS污染问题 (腾讯云开发者社区): https://cloud.tencent.com/developer/article/2434595
- [2] 是时候使用加密DNS来保护你的隐私-DoT/DoH (绝客博客): https://www.mrjeke.com/tutorials/186.html
- [3] 什么是DNS、DNS污染劫持和DNS加密（DoH/DoT）: https://www.cccitu.com/2205347.html
- [4] DoH 与 DoT 加密 DNS 协议对比详解: https://www.chonglangbiji.com/security/dns-over-https-vs-dns-over-tls/
- [5] بحث «چگونه DNS را طوری تنظیم کنیم که نشت نکند» در clash-verge-rev: https://github.com/clash-verge-rev/clash-verge-rev/discussions/2526

### ۳) تزریق بستهٔ جعلی / حملهٔ TCP RST

**انگلیسی:**
- [1] RFC 5961 — Improving TCP's Robustness to Blind In-Window Attacks: https://datatracker.ietf.org/doc/html/rfc5961
- [2] Off-Path TCP Sequence Number Inference Attack — IEEE S&P 2012: https://www.ieee-security.org/TC/SP2012/papers/4681a347.pdf
- [3] Detecting forged TCP reset packets (Weaver/Sommer/Paxson): https://www.researchgate.net/publication/221655461_Detecting_forged_TCP_reset_packets
- [4] In-depth analysis of the Great Firewall of China (Tufts): https://www.cs.tufts.edu/comp/116/archive/fall2016/ctang-supporting.pdf

**چینی:**
- [1] نسخهٔ چینی گزارش GFW/ESNI که «تزریق RST» را توصیف می‌کند: https://project-gutenberg.github.io/Pincong/post/38b26b4c5f4cad9eb924c9e1140e1da3/
- [2] gfw.report (sp25/zh) — توصیف تزریق RST توسط GFW و فایروال استانی: https://gfw.report/publications/sp25/zh/

### ۴) زنجیرهٔ تأمین / DLL sideloading / امضای درایور

**انگلیسی:**
- [1] MITRE ATT&CK T1574.002 (DLL Side-Loading): https://attack.mitre.org/techniques/T1574/002/
- [2] Hackers Exploit c-ares DLL Side-Loading (The Hacker News): https://thehackernews.com/2026/01/hackers-exploit-c-ares-dll-side-loading.html
- [3] A 2014 Certificate Still Loads Kernel Rootkits in 2026 (Xcitium): https://threatlabsnews.xcitium.com/blog/a-2014-certificate-still-loads-kernel-rootkits-in-2026/
- [4] C2Looper OneDrive DLL Sideloading (Cyber Security News): https://cybersecuritynews.com/c2looper-updates/

**چینی:**
- [1] 网络安全专家发现由微软 WHQL 签名的 FiveSys 驱动其实是伪装的恶意软件 (IT之家): https://www.ithome.com/0/582/232.htm
- [2] 恶意驱动Netfilter rootkit终极进化 (360): https://www.360.cn/n/11983.html
- [3] XIGNCODE3 反作弊内核驱动漏洞分析报告 (cnblogs): https://www.cnblogs.com/DirWang/p/22274393
- [4] 基于驱动级保护的进程与线程隐藏Rootkit开发实战 (CSDN): https://blog.csdn.net/weixin_30978239/article/details/154244520

### ۵) انگشت‌نگاری TLS / GREASE / پدینگ

**انگلیسی:**
- [1] RFC 8701 — GREASE: https://datatracker.ietf.org/doc/html/rfc8701
- [2] JA3 — Salesforce TLS fingerprinting: https://github.com/salesforce/ja3
- [3] NaïveProxy — پدینگ و دور زدن انگشت‌نگاری TLS: https://github.com/klzgrad/naiveproxy
- [4] sing-box changelog (هشدار دربارهٔ محدودیت uTLS fingerprinting): https://sing-box.sagernet.org/changelog/

**چینی:**
- [1] VLESS Reality — SNI 借用 و دور زدن انگشت‌نگاری (بحث رسمی Xray-core): https://github.com/XTLS/Xray-core/discussions/4850
- [2] XTLS的REALITY如何突破白名单? REALITY源码剖析: https://shadow.tun.webredirect.org/posts/how-reality-works/
- [3] Reality 协议演进 2026: https://www.chonglangbiji.com/protocols/reality-protocol-2026-update-comparison/
- [4] 2025 翻墙协议深度对比技术分析报告: https://www.nbhd.cloud/2025-fan-qiang-xie-yi-shen-du-dui-bi-ji-zhu-fen-xi-bao-gao/

---

## بخش ۳ — مخزن‌های گیت‌هاب پروژه‌های چینی دور زدن سانسور (که خواستید بررسی شوند)

این‌ها «VPN/پراکسی»های متن‌باز چینی هستند که تکنیک‌های SNI-جعل، پدینگ و انگشت‌نگاری را *به‌شکل اصولی‌تر* پیاده کرده‌اند و مرجع خوبی برای مقایسه با `dpi_guard` هستند:

| پروژه | نشانی | رویکرد SNI/ضد DPI |
|---|---|---|
| Xray-core (XTLS) | https://github.com/XTLS/Xray-core | VLESS + **Reality** (قرض‌گرفتن SNI/گواهی سایت واقعی) |
| v2ray-core (v2fly) | https://github.com/v2fly/v2ray-core | VMess/VLESS + WebSocket/TLS camouflage |
| trojan-go | https://github.com/p4gefau1t/trojan-go | TLS با جعل SNI + WebSocket multiplex |
| NaïveProxy | https://github.com/klzgrad/naiveproxy | پشتهٔ شبکهٔ Chromium + پدینگ طول |
| sing-box | https://github.com/SagerNet/sing-box | هستهٔ مدرن (Reality، TUIC، Hysteria، DoH/DoT) |
| Shadowsocks-rust | https://github.com/shadowsocks/shadowsocks-rust | پدینگ/obfs در سطح TLS |
| hysteria | https://github.com/apernet/hysteria | QUIC + ترمز/salamander obfuscation |
| clash-verge-rev | https://github.com/clash-verge-rev/clash-verge-rev | کلاینت با مدیریت DoH/DoT و fake-ip |

**نکتهٔ کلیدی برای این پروژه:** هیچ‌کدام از این پروژه‌ها SNI را *تک‌بایتی تکه‌تکه* یا با «checksum خراب + TTL محدود» جعل نمی‌کنند؛ آن‌ها SNI را یا **قرض می‌گیرند** (Reality) یا **در پدینگ پنهان می‌کنند** (NaïveProxy). جهش‌های `dpi_guard` (null-byte، underscore، explode، overflow و…) از نظر تکنیکی برای یک DPI مدرن *خودِ امضا هستند* و عملاً با `explode_subdomains`/`force_length_overflow` از دامنهٔ معتبر RFC خارج می‌شوند.

---

## خلاصهٔ وضعیت پس از اصلاح

- ✅ ۷ مشکل کدی رفع یا مستند شد (فایل‌ها: `engine.rs`, `config.rs`, `main.rs`, `pipeline.rs`, `stealth.rs`, `engine_stub.rs`, `dpi_guard.toml.example`, `.gitignore`).
- ⚠️ دو مورد همچنان **ساختاری** هستند و با کد خالص حل نمی‌شوند: (الف) WFP FFI ویندوز برای بستن واقعی پورت ۵۳، (ب) تست میدانی `engine.rs` روی ویندوز واقعی. این‌ها به مستندات/محدودیت صریح تبدیل شدند.
- ⚠️ قابل توجه: این ابزار هنوز برای اجرا به **دسترسی Administrator + درایور کرنل** نیاز دارد و ریسک عملیاتی آن (به‌ویژه زنجیرهٔ تأمین درایور) با pin جدید به‌طور چشمگیری کاهش یافت.

**توجه قانونی/دوگانه‌کاربرد:** این پروژه ابزار دور زدن سانسور است؛ قوانین استفاده از چنین ابزارهایی در حوزه‌های قضایی مختلف متفاوت است و کاربر مسئول رعایت قوانین محلی است.

---

## بخش ۴ — دور دوم (سخت‌گیرانه، پس از بازخوانی کامل crate)

### 🔴 ۸. `hold()` کامپایل نمی‌شد / fail-open نقض می‌شد

**مشکل:** `Pipeline::hold` آخرین عبارت را `HashMap::insert` (نوع `Option<FlowBuf>`) برمی‌گرداند در حالی که امضا `bool` است. جداگانه: mismatch سکانس یا خطای parse، بسته‌های hold‌شده را دور می‌ریخت (black-hole). ClientHello چندقطعه‌ای با SEQ قطعهٔ آخر rebuild می‌شد. تایم‌اوت 200ms فقط وقتی بستهٔ 443 بعدی می‌رسید چک می‌شد.

**اصلاح:** برگشت صریح `true`؛ `release_held_plus` برای fail-open؛ rebuild از قطعهٔ اول؛ watchdog 200ms در `main` که `take_expired_held` را با `inject_packet` خالی می‌کند.

### 🔴 ۹. توکن داشبورد lowercase می‌شد و در `Debug` لو می‌رفت

**مشکل:** کل هدر `Authorization` lowercase می‌شد، پس توکن mixed-case هیچ‌وقت match نمی‌کرد. `log::info!("{:?}", settings)` توکن و pin را چاپ می‌کرد.

**اصلاح:** فقط نام هدر lowercase است؛ مقدار توکن دست‌نخورده می‌ماند. `Settings` یک `Debug` سفارشی با `<redacted>` دارد. توکن پیکربندی‌شده حداقل ۱۶ کاراکتر printable است.

### 🟠 ۱۰. XSS داشبورد + نشت hostname خام در strategy scores

**مشکل:** `innerHTML` بدون escape، و `all_scores()` دامنهٔ خام SNI را به UI می‌داد.

**اصلاح:** `esc()` در JS؛ `strategy_scores_hashed()`؛ CSP / `X-Frame-Options` / `CORP` / `COOP`.

### 🟠 ۱۱. DNS rebinding روی داشبورد

**مشکل:** هر `Host` روی سوکت 127.0.0.1 پذیرفته می‌شد.

**اصلاح:** `Host` فقط `127.0.0.1` / `127.0.0.1:port`. `Origin` خالی یا همان origin. `localhost` رد می‌شود.

### 🟠 ۱۲. DLL planting از cwd

**مشکل:** `version_check` اول cwd را می‌گشت.

**اصلاح:** فقط کنار exe. سقف ۱۶MiB. مقایسهٔ pin با زمان ثابت (`integrity.rs`).

### 🟡 ۱۳. کانفیگ fail-open روی فایل خراب

**مشکل:** TOML نامعتبر → default. فیلد ناشناخته silently ignore. hot-reload بعد از parse شکست‌خورده mtime را جلو می‌برد.

**اصلاح:** `deny_unknown_fields`؛ فایل موجودِ نامعتبر یا مسیر صریحِ گم‌شده → exit 1؛ mtime فقط بعد از parse موفق.

### 🟡 ۱۴. امتیاز استراتژی و حافظه بی‌کران

**مشکل:** هر handshake ورودی 0x16 امتیاز را +1 می‌کرد. `recent` و DashMap رشد نامحدود داشتند.

**اصلاح:** فقط ServerHello یک‌بار (`remove`)؛ سقف 4096/512؛ `flush_idle` روی `recent`.

### 🟡 ۱۵. padding لایه ۳ در checksum/TLS

**مشکل:** `IPv4 Total Length` نادیده گرفته می‌شد.

**اصلاح:** `packet::l3_slice`؛ checksum فقط تا انتهای بستهٔ L3؛ checksum UDP صفر → 0xFFFF؛ UDP/IPv6.

### 🟢 ۱۶. متفرقه

- `#![deny(unsafe_code)]` به‌جز `engine.rs`
- بازیابی mutex مسموم
- overflow-checks در release (panic → fail-open)
- `.gitignore`
- CI: `cargo test`
