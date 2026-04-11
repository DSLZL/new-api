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


def _make_p0_fields(seed: str, source: str = "localStorage") -> dict:
    """构造 P0 字段（JA4/ETag/PersistentID/WebRTC）。"""
    return {
        "ja4": f"ja4_{_sha256(seed + ':ja4')}",
        "etag_id": f"etag_{_sha256(seed + ':etag')}",
        "persistent_id": f"pid_{_sha256(seed + ':pid')}",
        "id_source": source,
        "webrtc_local_ips": ["192.168.1.100"],
        "webrtc_public_ips": ["203.0.113.10"],
    }


def _make_p1_p2_fields(
    seed: str,
    dns_resolver_ip: str = "223.5.5.5",
    media_device_count: str = "3-1-1",
    media_device_total: int = 5,
    speech_voice_count: int = 9,
    speech_local_voice_count: int = 3,
) -> dict:
    """构造 P1/P2 字段（深度设备指纹 + DNS 泄露）。"""
    return {
        "webgl_deep_hash": f"wgdeep_{_sha256(seed + ':webgl_deep')}",
        "client_rects_hash": f"rects_{_sha256(seed + ':client_rects')}",
        "media_devices_hash": f"media_{_sha256(seed + ':media_devices')}",
        "media_device_group_hash": f"mdg_{_sha256(seed + ':media_group')}",
        "media_device_count": media_device_count,
        "media_device_total": media_device_total,
        "speech_voices_hash": f"speech_{_sha256(seed + ':speech_voices')}",
        "speech_voice_count": speech_voice_count,
        "speech_local_voice_count": speech_local_voice_count,
        "dns_resolver_ip": dns_resolver_ip,
    }


def _apply_header_profile(headers: dict, profile: str = "chrome_cn") -> dict:
    """补齐 HTTP Header 指纹相关头部，覆盖 Accept/CH/Fetch 维度。"""
    merged = dict(headers)
    profiles = {
        "chrome_cn": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Dest": "document",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="99"',
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-CH-UA-Mobile": "?0",
        },
        "firefox_cn": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.7",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "document",
        },
        "safari_cn": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Dest": "document",
        },
        "chrome_en": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Dest": "document",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="99"',
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-CH-UA-Mobile": "?0",
        },
    }
    merged.update(profiles.get(profile, profiles["chrome_cn"]))
    return merged


# ──────────────────────────────────────────────────────────────────────
# 数据类
# ──────────────────────────────────────────────────────────────────────

@dataclass
class BrowserProfile:
    """一个浏览器会话的完整信息"""
    headers: dict = field(default_factory=dict)   # HTTP 请求头（含 User-Agent）
    sim_ip: str = ""                               # 写入 X-Real-IP 的模拟 IP
    payload: dict = field(default_factory=dict)   # POST /api/fingerprint/report 的 body
    scenario: str = ""                             # 场景 ID (1-6)
    label: str = ""                                # 人类可读描述


# ──────────────────────────────────────────────────────────────────────
# 场景生成器
# ──────────────────────────────────────────────────────────────────────

class FingerprintScenarios:
    """
    Final 六类测试场景：
      1 - 同设备高分
      2 - 同设备隐身中高分（JA4 + 行为）
      3 - 同设备 VPN 中高分（WebRTC + 设备指纹）
      4 - 同设备清缓存中高分（ETag + 设备指纹）
      5 - 不同设备同一人中分（行为 + 时序）
      6 - 完全不同低分
    """

    # 固定 seed —— 保证六类场景多次运行结果稳定
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

    # ── 场景 1: 同设备高分 ───────────────────────────────────────────

    def scenario_1_same_device_high(self, sim_ip: str = "203.0.113.10") -> list[BrowserProfile]:
        """同设备 + 同浏览器 + 不同账号，预期高分。"""
        shared_hw = self._get_fp()
        shared_local_id = _make_fixed_local_id(self.DEVICE_SEED)
        canvas = _sha256(self.DEVICE_SEED + ":canvas")
        webgl = _sha256(self.DEVICE_SEED + ":webgl")
        audio = _sha256(self.DEVICE_SEED + ":audio")
        fonts = _sha256(self.DEVICE_SEED + ":fonts")
        renderer = "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)"
        vendor = "Google Inc. (NVIDIA)"
        composite = _sha256(canvas + webgl + audio + fonts)

        payload_a = {
            **shared_hw,
            **_make_p0_fields(self.DEVICE_SEED + ":s1"),
            **_make_p1_p2_fields(self.DEVICE_SEED + ":s1", dns_resolver_ip="223.5.5.5"),
            "canvas_hash": canvas,
            "webgl_hash": webgl,
            "webgl_vendor": vendor,
            "webgl_renderer": renderer,
            "audio_hash": audio,
            "fonts_hash": fonts,
            "fonts_list": "Arial,Times New Roman,Helvetica,Verdana,Georgia",
            "local_device_id": shared_local_id,
            "composite_hash": composite,
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": True,
            "keystroke": {
                "avgHoldTime": 94,
                "stdHoldTime": 16,
                "avgFlightTime": 116,
                "stdFlightTime": 21,
                "typingSpeed": 5.2,
                "sampleCount": 150,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 114, "stdFlightTime": 15, "sampleCount": 45},
                    {"digraph": "alpha->digit", "avgFlightTime": 127, "stdFlightTime": 18, "sampleCount": 33},
                ],
            },
            "mouse": {
                "avgSpeed": 1460,
                "maxSpeed": 2380,
                "speedStd": 168,
                "avgAcceleration": 340,
                "accStd": 72,
                "directionChangeRate": 0.23,
                "avgScrollDelta": 104,
                "scrollDeltaMode": 0,
                "sampleCount": 92,
                "clickDistribution": {
                    "topLeft": 0.21,
                    "topRight": 0.29,
                    "bottomLeft": 0.24,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733600400),
            "session_end_at": int(1733601000),
            "session_id": f"s1-a-{_sha256(self.DEVICE_SEED)}",
        }

        payload_b = {
            **payload_a,
            "session_start_at": int(1733602200),
            "session_end_at": int(1733602800),
            "session_id": f"s1-b-{_sha256(self.DEVICE_SEED)}",
        }

        headers = self._get_headers()
        return [
            BrowserProfile(headers=headers, sim_ip=sim_ip, payload=payload_a, scenario="1", label="场景1-账号A"),
            BrowserProfile(headers=headers, sim_ip=sim_ip, payload=payload_b, scenario="1", label="场景1-账号B"),
        ]

    # ── 场景 3: 同设备 VPN 中高分 ───────────────────────────────────

    def scenario_3_vpn_medium_high(self, ip_normal: str = "203.0.113.10", ip_vpn: str = "198.51.100.42") -> list[BrowserProfile]:
        """同设备 VPN 场景：IP 变化，但 WebRTC 与设备特征保持。"""
        hw = self._get_fp()
        seed = self.DEVICE_SEED + ":vpn"
        canvas = _sha256(seed + ":canvas")
        webgl = _sha256(seed + ":webgl")
        audio = _sha256(seed + ":audio")
        fonts = _sha256(seed + ":fonts")
        shared_local_id = _make_fixed_local_id(seed)
        shared_local_webrtc = "192.168.1.100"
        shared_public_webrtc = "203.0.113.66"

        payload_a = {
            **hw,
            **_make_p1_p2_fields(seed + ":s3", dns_resolver_ip="119.29.29.29"),
            "ja4": f"ja4_{_sha256(seed + ':ja4')}",
            "etag_id": f"etag_{_sha256(seed + ':etag')}",
            "persistent_id": "",
            "id_source": "",
            "canvas_hash": canvas,
            "webgl_hash": webgl,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
            "audio_hash": audio,
            "fonts_hash": fonts,
            "local_device_id": shared_local_id,
            "composite_hash": _sha256(seed + ":composite"),
            "webrtc_local_ips": [shared_local_webrtc],
            "webrtc_public_ips": [shared_public_webrtc],
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": True,
            "session_start_at": int(1733736000),
            "session_end_at": int(1733736600),
            "session_id": f"s3-a-{_sha256(seed)}",
        }
        payload_b = {
            **payload_a,
            "session_start_at": int(1733739000),
            "session_end_at": int(1733739600),
            "session_id": f"s3-b-{_sha256(seed)}",
        }
        headers = self._get_headers()
        return [
            BrowserProfile(headers=headers, sim_ip=ip_normal, payload=payload_a, scenario="3", label="场景3-VPN前"),
            BrowserProfile(headers=headers, sim_ip=ip_vpn, payload=payload_b, scenario="3", label="场景3-VPN后"),
        ]

    # ── 场景 2: 同设备隐身中高分 ───────────────────────────────────

    def scenario_2_incognito_medium_high(self, sim_ip: str = "203.0.113.10") -> list[BrowserProfile]:
        """同设备隐身：清空本地设备哈希，保留 JA4 + 行为 + 时序。"""
        hw = self._get_fp()
        seed = self.DEVICE_SEED + ":incognito"
        shared_ja4 = f"ja4_{_sha256(seed + ':ja4')}"

        payload_a = {
            **hw,
            **_make_p0_fields(seed + ":a"),
            **_make_p1_p2_fields(seed + ":shared", dns_resolver_ip="223.6.6.6"),
            "ja4": shared_ja4,
            "etag_id": "",
            "persistent_id": "",
            "id_source": "",
            "canvas_hash": "",
            "webgl_hash": "",
            "webgl_vendor": "",
            "webgl_renderer": "",
            "audio_hash": "",
            "fonts_hash": "",
            "fonts_list": "",
            "local_device_id": "",
            "composite_hash": "",
            "webrtc_local_ips": ["192.168.1.100"],
            "webrtc_public_ips": [sim_ip],
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": False,
            "keystroke": {
                "avgHoldTime": 97,
                "stdHoldTime": 18,
                "avgFlightTime": 120,
                "stdFlightTime": 24,
                "typingSpeed": 4.9,
                "sampleCount": 142,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 118, "stdFlightTime": 16, "sampleCount": 39},
                    {"digraph": "alpha->digit", "avgFlightTime": 132, "stdFlightTime": 19, "sampleCount": 31},
                ],
            },
            "mouse": {
                "avgSpeed": 1440,
                "maxSpeed": 2320,
                "speedStd": 171,
                "avgAcceleration": 332,
                "accStd": 71,
                "directionChangeRate": 0.23,
                "avgScrollDelta": 108,
                "scrollDeltaMode": 0,
                "sampleCount": 89,
                "clickDistribution": {
                    "topLeft": 0.22,
                    "topRight": 0.30,
                    "bottomLeft": 0.22,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733683200),
            "session_end_at": int(1733683800),
            "session_id": f"s2-a-{_sha256(seed)}",
        }

        payload_b = {
            **hw,
            **_make_p0_fields(seed + ":b"),
            **_make_p1_p2_fields(seed + ":shared", dns_resolver_ip="223.6.6.6"),
            "ja4": shared_ja4,
            "etag_id": "",
            "persistent_id": "",
            "id_source": "",
            "canvas_hash": "",
            "webgl_hash": "",
            "webgl_vendor": "",
            "webgl_renderer": "",
            "audio_hash": "",
            "fonts_hash": "",
            "fonts_list": "",
            "local_device_id": "",
            "composite_hash": "",
            "webrtc_local_ips": ["192.168.1.100"],
            "webrtc_public_ips": [sim_ip],
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": False,
            "keystroke": {
                "avgHoldTime": 100,
                "stdHoldTime": 20,
                "avgFlightTime": 124,
                "stdFlightTime": 25,
                "typingSpeed": 4.7,
                "sampleCount": 138,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 121, "stdFlightTime": 17, "sampleCount": 37},
                    {"digraph": "alpha->digit", "avgFlightTime": 136, "stdFlightTime": 20, "sampleCount": 29},
                ],
            },
            "mouse": {
                "avgSpeed": 1470,
                "maxSpeed": 2280,
                "speedStd": 176,
                "avgAcceleration": 326,
                "accStd": 73,
                "directionChangeRate": 0.24,
                "avgScrollDelta": 113,
                "scrollDeltaMode": 0,
                "sampleCount": 85,
                "clickDistribution": {
                    "topLeft": 0.20,
                    "topRight": 0.31,
                    "bottomLeft": 0.23,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733686200),
            "session_end_at": int(1733686800),
            "session_id": f"s2-b-{_sha256(seed)}",
        }

        h1 = self._get_headers()
        h2 = self._get_headers(browser="firefox")
        h1["X-JA4-Fingerprint"] = shared_ja4
        h2["X-JA4-Fingerprint"] = shared_ja4
        return [
            BrowserProfile(headers=h1, sim_ip=sim_ip, payload=payload_a, scenario="2", label="场景2-隐身样本A"),
            BrowserProfile(headers=h2, sim_ip=sim_ip, payload=payload_b, scenario="2", label="场景2-隐身样本B"),
        ]

    # ── 场景 4: 清缓存中高分 ─────────────────────────────────────────

    def scenario_4_clear_cache(self, sim_ip: str = "203.0.113.10") -> list[BrowserProfile]:
        """清缓存：保留 ETag，弱化持久ID，依赖 ETag + 设备侧信号达到中高分。"""
        hw = self._get_fp()
        seed = self.DEVICE_SEED + ":clear-cache"
        shared_etag = f"etag_{_sha256(seed + ':etag')}"

        before_clear = {
            **hw,
            **_make_p0_fields(seed + ":before"),
            **_make_p1_p2_fields(seed + ":shared", dns_resolver_ip="180.76.76.76"),
            "ja4": f"ja4_{_sha256(seed + ':ja4')}",
            "etag_id": shared_etag,
            "persistent_id": "",
            "id_source": "",
            "webrtc_local_ips": ["192.168.1.100"],
            "webrtc_public_ips": [sim_ip],
            "canvas_hash": _sha256(seed + ":canvas"),
            "webgl_hash": _sha256(seed + ":webgl"),
            "audio_hash": _sha256(seed + ":audio"),
            "fonts_hash": _sha256(seed + ":fonts"),
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "webgl_renderer": "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
            "local_device_id": _make_fixed_local_id(seed),
            "composite_hash": _sha256(seed + ":composite"),
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": True,
            "keystroke": {
                "avgHoldTime": 96,
                "stdHoldTime": 17,
                "avgFlightTime": 118,
                "stdFlightTime": 22,
                "typingSpeed": 5.1,
                "sampleCount": 140,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 116, "stdFlightTime": 15, "sampleCount": 40},
                    {"digraph": "alpha->digit", "avgFlightTime": 130, "stdFlightTime": 18, "sampleCount": 32},
                ],
            },
            "mouse": {
                "avgSpeed": 1420,
                "maxSpeed": 2350,
                "speedStd": 165,
                "avgAcceleration": 335,
                "accStd": 70,
                "directionChangeRate": 0.22,
                "avgScrollDelta": 102,
                "scrollDeltaMode": 0,
                "sampleCount": 90,
                "clickDistribution": {
                    "topLeft": 0.22,
                    "topRight": 0.28,
                    "bottomLeft": 0.24,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733803200),
            "session_end_at": int(1733803800),
            "session_id": f"s4-before-{_sha256(seed)}",
        }

        after_clear = {
            **hw,
            **_make_p0_fields(seed + ":after"),
            **_make_p1_p2_fields(seed + ":shared", dns_resolver_ip="180.76.76.76"),
            "ja4": f"ja4_{_sha256(seed + ':ja4')}",
            "etag_id": shared_etag,
            "persistent_id": "",
            "id_source": "etag_cookie",
            "webrtc_local_ips": ["192.168.1.100"],
            "webrtc_public_ips": [sim_ip],
            "canvas_hash": "",
            "webgl_hash": "",
            "audio_hash": "",
            "fonts_hash": "",
            "webgl_vendor": "",
            "webgl_renderer": "",
            "local_device_id": "",
            "composite_hash": "",
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "do_not_track": "1",
            "cookie_enabled": True,
            "keystroke": {
                "avgHoldTime": 99,
                "stdHoldTime": 19,
                "avgFlightTime": 122,
                "stdFlightTime": 24,
                "typingSpeed": 4.9,
                "sampleCount": 138,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 119, "stdFlightTime": 17, "sampleCount": 38},
                    {"digraph": "alpha->digit", "avgFlightTime": 134, "stdFlightTime": 19, "sampleCount": 30},
                ],
            },
            "mouse": {
                "avgSpeed": 1460,
                "maxSpeed": 2290,
                "speedStd": 170,
                "avgAcceleration": 328,
                "accStd": 72,
                "directionChangeRate": 0.23,
                "avgScrollDelta": 109,
                "scrollDeltaMode": 0,
                "sampleCount": 86,
                "clickDistribution": {
                    "topLeft": 0.21,
                    "topRight": 0.30,
                    "bottomLeft": 0.23,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733821200),
            "session_end_at": int(1733821800),
            "session_id": f"s4-after-{_sha256(seed)}",
        }

        h = self._get_headers()
        return [
            BrowserProfile(headers=h, sim_ip=sim_ip, payload=before_clear, scenario="4", label="场景4-清缓存前"),
            BrowserProfile(headers=h, sim_ip=sim_ip, payload=after_clear, scenario="4", label="场景4-清缓存后"),
        ]

    def scenario_5_same_person_diff_device(self, ip_a: str = "203.0.113.10", ip_b: str = "203.0.113.77") -> list[BrowserProfile]:
        """不同设备但行为/时序接近，用于同一人中分场景。"""
        hw_a = self._get_fp()
        hw_b = self._get_fp()
        seed_a = self.DEVICE_SEED + ":person-device-a"
        seed_b = self.DEVICE_SEED + ":person-device-b"

        p1 = {
            **hw_a,
            **_make_p0_fields(seed_a),
            **_make_p1_p2_fields(seed_a + ":s5a", dns_resolver_ip="114.114.114.114"),
            "persistent_id": "",
            "etag_id": "",
            "id_source": "",
            "ja4": "",
            "canvas_hash": _sha256(seed_a + ":canvas"),
            "webgl_hash": _sha256(seed_a + ":webgl"),
            "audio_hash": _sha256(seed_a + ":audio"),
            "fonts_hash": _sha256(seed_a + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash": _sha256(seed_a + ":composite"),
            "webrtc_local_ips": ["10.10.1.20"],
            "webrtc_public_ips": ["198.51.100.201"],
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "platform": "Win32",
            "languages": "zh-CN,en",
            "screen_width": 1920,
            "screen_height": 1080,
            "cpu_cores": 8,
            "device_memory": 8.0,
            "keystroke": {
                "avgHoldTime": 98,
                "stdHoldTime": 16,
                "avgFlightTime": 121,
                "stdFlightTime": 23,
                "typingSpeed": 5.0,
                "sampleCount": 150,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 119, "stdFlightTime": 16, "sampleCount": 42},
                    {"digraph": "digit->alpha", "avgFlightTime": 132, "stdFlightTime": 20, "sampleCount": 33},
                ],
            },
            "mouse": {
                "avgSpeed": 1480,
                "maxSpeed": 2450,
                "speedStd": 175,
                "avgAcceleration": 342,
                "accStd": 73,
                "directionChangeRate": 0.24,
                "avgScrollDelta": 106,
                "scrollDeltaMode": 0,
                "sampleCount": 95,
                "clickDistribution": {
                    "topLeft": 0.20,
                    "topRight": 0.32,
                    "bottomLeft": 0.22,
                    "bottomRight": 0.26,
                },
            },
            "session_start_at": int(1733911200),
            "session_end_at": int(1733912100),
            "session_id": f"s5-a-{_sha256(seed_a)}",
        }

        p2 = {
            **hw_b,
            **_make_p0_fields(seed_b),
            **_make_p1_p2_fields(seed_b + ":s5b", dns_resolver_ip="114.114.114.114"),
            "persistent_id": "",
            "etag_id": "",
            "id_source": "",
            "ja4": "",
            "canvas_hash": _sha256(seed_b + ":canvas"),
            "webgl_hash": _sha256(seed_b + ":webgl"),
            "audio_hash": _sha256(seed_b + ":audio"),
            "fonts_hash": _sha256(seed_b + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash": _sha256(seed_b + ":composite"),
            "webrtc_local_ips": ["10.20.8.15"],
            "webrtc_public_ips": ["198.51.100.202"],
            "timezone": "Asia/Shanghai",
            "tz_offset": -480,
            "platform": "MacIntel",
            "languages": "zh-CN,en",
            "screen_width": 1512,
            "screen_height": 982,
            "cpu_cores": 8,
            "device_memory": 8.0,
            "keystroke": {
                "avgHoldTime": 101,
                "stdHoldTime": 18,
                "avgFlightTime": 124,
                "stdFlightTime": 25,
                "typingSpeed": 4.8,
                "sampleCount": 146,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 122, "stdFlightTime": 17, "sampleCount": 40},
                    {"digraph": "digit->alpha", "avgFlightTime": 136, "stdFlightTime": 21, "sampleCount": 31},
                ],
            },
            "mouse": {
                "avgSpeed": 1510,
                "maxSpeed": 2390,
                "speedStd": 182,
                "avgAcceleration": 336,
                "accStd": 76,
                "directionChangeRate": 0.25,
                "avgScrollDelta": 111,
                "scrollDeltaMode": 0,
                "sampleCount": 91,
                "clickDistribution": {
                    "topLeft": 0.19,
                    "topRight": 0.33,
                    "bottomLeft": 0.23,
                    "bottomRight": 0.25,
                },
            },
            "session_start_at": int(1733913000),
            "session_end_at": int(1733913900),
            "session_id": f"s5-b-{_sha256(seed_b)}",
        }

        return [
            BrowserProfile(headers=self._get_headers(os="windows", browser="chrome"), sim_ip=ip_a, payload=p1, scenario="5", label="场景5-设备A"),
            BrowserProfile(headers=self._get_headers(os="macos", browser="safari"), sim_ip=ip_b, payload=p2, scenario="5", label="场景5-设备B"),
        ]

    def scenario_6_completely_different(self, ip_x: str = "10.20.30.40", ip_y: str = "192.0.2.99") -> list[BrowserProfile]:
        """完全不同设备 + 网络 + 行为，预期低分。"""
        hw1 = self._get_fp()
        hw2 = self._get_fp()
        seed_x = _rand_hash()
        seed_y = _rand_hash()
        p1 = {
            **hw1,
            **_make_p0_fields(seed_x),
            **_make_p1_p2_fields(
                seed_x + ":s6x",
                dns_resolver_ip="9.9.9.9",
                media_device_count="7-3-2",
                media_device_total=12,
                speech_voice_count=14,
                speech_local_voice_count=6,
            ),
            "canvas_hash": _sha256(seed_x + ":canvas"),
            "webgl_hash": _sha256(seed_x + ":webgl"),
            "webgl_vendor": "Google Inc. (Intel)",
            "webgl_renderer": "ANGLE (Intel UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)",
            "audio_hash": _sha256(seed_x + ":audio"),
            "fonts_hash": _sha256(seed_x + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash": _sha256(seed_x),
            "timezone": "America/New_York",
            "tz_offset": 300,
            "do_not_track": "unspecified",
            "cookie_enabled": True,
            "webrtc_local_ips": ["192.168.10.23"],
            "webrtc_public_ips": ["203.0.113.123"],
            "keystroke": {
                "avgHoldTime": 165,
                "stdHoldTime": 44,
                "avgFlightTime": 210,
                "stdFlightTime": 66,
                "typingSpeed": 2.2,
                "sampleCount": 130,
                "commonDigraphs": [
                    {"digraph": "digit->digit", "avgFlightTime": 218, "stdFlightTime": 62, "sampleCount": 37},
                    {"digraph": "symbol->alpha", "avgFlightTime": 232, "stdFlightTime": 75, "sampleCount": 21},
                ],
            },
            "mouse": {
                "avgSpeed": 690,
                "maxSpeed": 1200,
                "speedStd": 330,
                "avgAcceleration": 130,
                "accStd": 95,
                "directionChangeRate": 0.08,
                "avgScrollDelta": 36,
                "scrollDeltaMode": 1,
                "sampleCount": 88,
                "clickDistribution": {
                    "topLeft": 0.55,
                    "topRight": 0.08,
                    "bottomLeft": 0.30,
                    "bottomRight": 0.07,
                },
            },
            "session_start_at": int(1733990400),
            "session_end_at": int(1733991300),
            "session_id": f"s6-x-{_sha256(seed_x)}",
        }
        p2 = {
            **hw2,
            **_make_p0_fields(seed_y),
            **_make_p1_p2_fields(
                seed_y + ":s6y",
                dns_resolver_ip="1.1.1.1",
                media_device_count="2-1-0",
                media_device_total=3,
                speech_voice_count=5,
                speech_local_voice_count=1,
            ),
            "canvas_hash": _sha256(seed_y + ":canvas"),
            "webgl_hash": _sha256(seed_y + ":webgl"),
            "webgl_vendor": "Google Inc. (AMD)",
            "webgl_renderer": "ANGLE (AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)",
            "audio_hash": _sha256(seed_y + ":audio"),
            "fonts_hash": _sha256(seed_y + ":fonts"),
            "local_device_id": _rand_local_id(),
            "composite_hash": _sha256(seed_y),
            "timezone": "Europe/London",
            "tz_offset": 0,
            "do_not_track": "1",
            "cookie_enabled": True,
            "webrtc_local_ips": ["10.8.0.42"],
            "webrtc_public_ips": ["198.51.100.88"],
            "keystroke": {
                "avgHoldTime": 72,
                "stdHoldTime": 14,
                "avgFlightTime": 92,
                "stdFlightTime": 18,
                "typingSpeed": 6.8,
                "sampleCount": 135,
                "commonDigraphs": [
                    {"digraph": "alpha->alpha", "avgFlightTime": 88, "stdFlightTime": 14, "sampleCount": 42},
                    {"digraph": "alpha->digit", "avgFlightTime": 96, "stdFlightTime": 17, "sampleCount": 29},
                ],
            },
            "mouse": {
                "avgSpeed": 2320,
                "maxSpeed": 3650,
                "speedStd": 140,
                "avgAcceleration": 510,
                "accStd": 58,
                "directionChangeRate": 0.40,
                "avgScrollDelta": 185,
                "scrollDeltaMode": 2,
                "sampleCount": 92,
                "clickDistribution": {
                    "topLeft": 0.10,
                    "topRight": 0.56,
                    "bottomLeft": 0.09,
                    "bottomRight": 0.25,
                },
            },
            "session_start_at": int(1734033600),
            "session_end_at": int(1734034500),
            "session_id": f"s6-y-{_sha256(seed_y)}",
        }
        return [
            BrowserProfile(
                headers=self._get_headers(os="windows", browser="chrome"),
                sim_ip=ip_x, payload=p1,
                scenario="6", label="场景6-用户甲",
            ),
            BrowserProfile(
                headers=self._get_headers(os="macos", browser="safari"),
                sim_ip=ip_y, payload=p2,
                scenario="6", label="场景6-用户乙",
            ),
        ]
