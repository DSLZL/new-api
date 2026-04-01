"""指纹生成器 - 使用 browserforge 生成真实浏览器指纹并注入场景变量"""
import hashlib
import random
import string
from dataclasses import dataclass, field

# browserforge 在 import 时会触发网络下载，直接使用内置 fallback
BROWSERFORGE_OK = False
FingerprintGenerator = None
Screen = None
HeaderGenerator = None


# ──────────────────────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────────────────────

def _sha256(seed: str) -> str:
    """确定性哈希（前 16 字节 hex）—— 相同 seed 永远返回相同值"""
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _rand_hash() -> str:
    """完全随机哈希 —— 模拟不同设备"""
    return hashlib.sha256(
        ''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()
    ).hexdigest()[:16]


def _rand_local_id() -> str:
    """随机 UUID v4 风格本地设备 ID"""
    return '-'.join([
        ''.join(random.choices('0123456789abcdef', k=8)),
        ''.join(random.choices('0123456789abcdef', k=4)),
        '4' + ''.join(random.choices('0123456789abcdef', k=3)),
        random.choice('89ab') + ''.join(random.choices('0123456789abcdef', k=3)),
        ''.join(random.choices('0123456789abcdef', k=12)),
    ])


def _make_fixed_local_id(device_seed: str) -> str:
    """从 device_seed 生成固定的本地设备 ID"""
    h = hashlib.md5(device_seed.encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-4{h[13:16]}-{random.choice('89ab')}{h[17:20]}-{h[20:32]}"


# ──────────────────────────────────────────────────────────────────────
# 数据类
# ──────────────────────────────────────────────────────────────────────

@dataclass
class BrowserProfile:
    """一个浏览器会话的完整信息"""
    headers: dict = field(default_factory=dict)   # HTTP 请求头（含 User-Agent）
    sim_ip: str = ""                               # 写入 X-Real-IP 的模拟 IP
    payload: dict = field(default_factory=dict)   # POST /api/fingerprint/report 的 body
    scenario: str = ""                             # 场景 ID (a/b/c/d)
    label: str = ""                                # 人类可读描述


# ──────────────────────────────────────────────────────────────────────
# 场景生成器
# ──────────────────────────────────────────────────────────────────────

class FingerprintScenarios:
    """
    四个测试场景：
      A - 同设备双账号：相同 Canvas / WebGL / LocalDeviceID，相同 IP
      B - VPN 换 IP：Canvas/WebGL 相同，IP 不同（模拟用户挂 VPN）
      C - 无痕模式：所有浏览器哈希为空，仅靠 IP 关联
      D - 完全陌生人：不同设备 + 不同 IP
    """

    # 固定 seed —— 保证 A/B 场景两次运行哈希一致
    DEVICE_SEED = "test_device_alpha_001"

    def __init__(self):
        self._gen = None
        self._hgen = None
        if BROWSERFORGE_OK:
            self._gen = FingerprintGenerator(
                screen=Screen(min_width=1280, min_height=720),
                strict=False,
            )
            self._hgen = HeaderGenerator()

    # ── 内部：获取 browserforge 生成的头部（无则 fallback）──────────────

    def _get_headers(self, os: str = "windows", browser: str = "chrome") -> dict:
        if self._hgen:
            try:
                return dict(self._hgen.generate(
                    browser=browser,
                    os=os,
                    device="desktop",
                ))
            except Exception:
                pass
        # fallback
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }

    def _get_fp(self) -> dict:
        """从 browserforge 获取一份真实指纹的硬件 / 屏幕字段"""
        if self._gen:
            try:
                fp = self._gen.generate()
                nav = fp.navigator
                scr = fp.screen
                return {
                    "screen_width":  scr.width,
                    "screen_height": scr.height,
                    "color_depth":   scr.colorDepth,
                    "pixel_ratio":   float(scr.devicePixelRatio),
                    "cpu_cores":     getattr(nav, 'hardwareConcurrency', 4),
                    "device_memory": float(getattr(nav, 'deviceMemory', 8)),
                    "max_touch":     getattr(nav, 'maxTouchPoints', 0),
                    "platform":      getattr(nav, 'platform', 'Win32'),
                    "languages":     ','.join(getattr(nav, 'languages', ['zh-CN', 'en'])),
                }
            except Exception:
                pass
        # fallback
        return {
            "screen_width": 1920, "screen_height": 1080,
            "color_depth": 24, "pixel_ratio": 1.0,
            "cpu_cores": 8, "device_memory": 8.0,
            "max_touch": 0, "platform": "Win32",
            "languages": "zh-CN,zh,en",
        }

    # ── 场景 A: 同设备，不同账号 ──────────────────────────────────────

    def scenario_a(self, sim_ip: str = "203.0.113.10") -> list[BrowserProfile]:
        """返回两个指纹，canvas/webgl/local_device_id 完全相同"""
        shared_hw = self._get_fp()
        shared_local_id = _make_fixed_local_id(self.DEVICE_SEED)
        canvas  = _sha256(self.DEVICE_SEED + ":canvas")
        webgl   = _sha256(self.DEVICE_SEED + ":webgl")
        audio   = _sha256(self.DEVICE_SEED + ":audio")
        fonts   = _sha256(self.DEVICE_SEED + ":fonts")
        renderer = "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)"
        vendor   = "Google Inc. (NVIDIA)"
        composite = _sha256(canvas + webgl + audio + fonts)

        base_payload = {
            **shared_hw,
            "canvas_hash":     canvas,
            "webgl_hash":      webgl,
            "webgl_vendor":    vendor,
            "webgl_renderer":  renderer,
            "audio_hash":      audio,
            "fonts_hash":      fonts,
            "fonts_list":      "Arial,Times New Roman,Helvetica,Verdana,Georgia",
            "local_device_id": shared_local_id,
            "composite_hash":  composite,
            "timezone":        "Asia/Shanghai",
            "tz_offset":       -480,
            "do_not_track":    "1",
            "cookie_enabled":  True,
        }
        headers = self._get_headers()
        return [
            BrowserProfile(
                headers=headers, sim_ip=sim_ip,
                payload=base_payload,
                scenario="a", label="账号A1 - 同设备第一个账号",
            ),
            BrowserProfile(
                headers=headers, sim_ip=sim_ip,
                payload=base_payload,
                scenario="a", label="账号A2 - 同设备第二个账号（应被关联）",
            ),
        ]

    # ── 场景 B: 同设备 + VPN ──────────────────────────────────────────

    def scenario_b(self, ip_normal: str = "203.0.113.10",
                   ip_vpn: str = "198.51.100.42") -> list[BrowserProfile]:
        """返回两个指纹，canvas/webgl 相同但 IP 不同（VPN）"""
        hw = self._get_fp()
        canvas  = _sha256(self.DEVICE_SEED + ":canvas")
        webgl   = _sha256(self.DEVICE_SEED + ":webgl")
        audio   = _sha256(self.DEVICE_SEED + ":audio")
        fonts   = _sha256(self.DEVICE_SEED + ":fonts")
        renderer = "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)"
        shared_local_id = _make_fixed_local_id(self.DEVICE_SEED)
        composite = _sha256(canvas + webgl + audio + fonts)

        payload = {
            **hw,
            "canvas_hash":     canvas,
            "webgl_hash":      webgl,
            "webgl_vendor":    "Google Inc. (NVIDIA)",
            "webgl_renderer":  renderer,
            "audio_hash":      audio,
            "fonts_hash":      fonts,
            "local_device_id": shared_local_id,
            "composite_hash":  composite,
            "timezone":        "Asia/Shanghai",
            "tz_offset":       -480,
            "do_not_track":    "1",
            "cookie_enabled":  True,
        }
        headers = self._get_headers()
        return [
            BrowserProfile(
                headers=headers, sim_ip=ip_normal,
                payload=payload,
                scenario="b", label="账号B1 - 正常IP",
            ),
            BrowserProfile(
                headers=headers, sim_ip=ip_vpn,
                payload=payload,
                scenario="b", label="账号B2 - VPN换IP（应被Canvas关联）",
            ),
        ]

    # ── 场景 C: 无痕模式（清空所有浏览器哈希）────────────────────────

    def scenario_c(self, sim_ip: str = "203.0.113.10") -> list[BrowserProfile]:
        """无痕模式：无 canvas/webgl/audio/fonts/local_device_id，仅靠 IP"""
        hw = self._get_fp()
        blank_payload = {
            **hw,
            "canvas_hash":     "",
            "webgl_hash":      "",
            "webgl_vendor":    "",
            "webgl_renderer":  "",
            "audio_hash":      "",
            "fonts_hash":      "",
            "fonts_list":      "",
            "local_device_id": "",
            "composite_hash":  "",
            "timezone":        "Asia/Shanghai",
            "tz_offset":       -480,
            "do_not_track":    "1",
            "cookie_enabled":  False,
        }
        h1 = self._get_headers()
        h2 = self._get_headers(browser="firefox")  # 换一个浏览器模拟无痕
        return [
            BrowserProfile(
                headers=h1, sim_ip=sim_ip,
                payload=blank_payload,
                scenario="c", label="账号C1 - 无痕，同IP",
            ),
            BrowserProfile(
                headers=h2, sim_ip=sim_ip,
                payload=blank_payload,
                scenario="c", label="账号C2 - 无痕，同IP（应靠IP关联）",
            ),
        ]

    # ── 场景 D: 完全陌生人 ────────────────────────────────────────────

    def scenario_d(self, ip_x: str = "10.20.30.40",
                   ip_y: str = "192.0.2.99") -> list[BrowserProfile]:
        """完全不同设备 + 不同 IP，不应被关联"""
        hw1 = self._get_fp()
        hw2 = self._get_fp()
        seed_x = _rand_hash()
        seed_y = _rand_hash()
        p1 = {
            **hw1,
            "canvas_hash":     _sha256(seed_x + ":canvas"),
            "webgl_hash":      _sha256(seed_x + ":webgl"),
            "webgl_vendor":    "Google Inc. (Intel)",
            "webgl_renderer":  "ANGLE (Intel UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
            "audio_hash":      _sha256(seed_x + ":audio"),
            "fonts_hash":      _sha256(seed_x + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash":  _sha256(seed_x),
            "timezone":        "America/New_York",
            "tz_offset":       300,
            "do_not_track":    "unspecified",
            "cookie_enabled":  True,
        }
        p2 = {
            **hw2,
            "canvas_hash":     _sha256(seed_y + ":canvas"),
            "webgl_hash":      _sha256(seed_y + ":webgl"),
            "webgl_vendor":    "Google Inc. (AMD)",
            "webgl_renderer":  "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
            "audio_hash":      _sha256(seed_y + ":audio"),
            "fonts_hash":      _sha256(seed_y + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash":  _sha256(seed_y),
            "timezone":        "Europe/London",
            "tz_offset":       0,
            "do_not_track":    "1",
            "cookie_enabled":  True,
        }
        return [
            BrowserProfile(
                headers=self._get_headers(os="windows", browser="chrome"),
                sim_ip=ip_x, payload=p1,
                scenario="d", label="账号D1 - 陌生人甲",
            ),
            BrowserProfile(
                headers=self._get_headers(os="macos", browser="safari"),
                sim_ip=ip_y, payload=p2,
                scenario="d", label="账号D2 - 陌生人乙（不应关联）",
            ),
        ]
