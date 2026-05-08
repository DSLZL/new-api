"""手动验收造数脚本：生成高/中/低关联样本并打印对比结果。"""

import os
from dotenv import load_dotenv

from reporter import FingerprintReporter
from fingerprint_generator import BrowserProfile


def ks(avg_hold: float, speed: float) -> dict:
    return {
        "avgHoldTime": avg_hold,
        "stdHoldTime": 16,
        "avgFlightTime": 118,
        "stdFlightTime": 21,
        "typingSpeed": speed,
        "sampleCount": 150,
        "commonDigraphs": [
            {
                "digraph": "alpha->alpha",
                "avgFlightTime": 116,
                "stdFlightTime": 15,
                "sampleCount": 44,
            },
            {
                "digraph": "alpha->digit",
                "avgFlightTime": 129,
                "stdFlightTime": 18,
                "sampleCount": 33,
            },
        ],
    }


def ms(avg_speed: float, change_rate: float) -> dict:
    return {
        "avgSpeed": avg_speed,
        "maxSpeed": 2400,
        "speedStd": 170,
        "avgAcceleration": 338,
        "accStd": 72,
        "directionChangeRate": change_rate,
        "avgScrollDelta": 108,
        "scrollDeltaMode": 0,
        "sampleCount": 95,
        "clickDistribution": {
            "topLeft": 0.21,
            "topRight": 0.30,
            "bottomLeft": 0.23,
            "bottomRight": 0.26,
        },
    }


def make_headers(ua: str, lang: str = "zh-CN,zh;q=0.9,en;q=0.8") -> dict:
    return {
        "User-Agent": ua,
        "Accept-Language": lang,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Dest": "document",
    }


def make_profile(payload: dict, sim_ip: str, ua: str, lang: str = "zh-CN,zh;q=0.9,en;q=0.8") -> BrowserProfile:
    return BrowserProfile(
        headers=make_headers(ua, lang),
        sim_ip=sim_ip,
        payload=payload,
        scenario="manual",
        label="manual-seed",
    )


def build_payloads() -> tuple[dict, dict, dict, dict]:
    payload_a = {
        "local_device_id": "dev-high-001",
        "persistent_id": "pid-high-001",
        "id_source": "localStorage",
        "etag_id": "etag-high-001",
        "canvas_hash": "canvas-high-001",
        "webgl_hash": "webgl-high-001",
        "webgl_deep_hash": "webgl-deep-high-001",
        "client_rects_hash": "rects-high-001",
        "media_devices_hash": "media-high-001",
        "media_device_group_hash": "media-group-high-001",
        "media_device_count": "3-1-1",
        "media_device_total": 5,
        "speech_voices_hash": "speech-high-001",
        "speech_voice_count": 9,
        "speech_local_voice_count": 3,
        "audio_hash": "audio-high-001",
        "fonts_hash": "fonts-high-001",
        "fonts_list": "Arial,Helvetica,Times New Roman",
        "screen_width": 1920,
        "screen_height": 1080,
        "color_depth": 24,
        "pixel_ratio": 1.0,
        "cpu_cores": 8,
        "device_memory": 8.0,
        "max_touch": 0,
        "timezone": "Asia/Shanghai",
        "tz_offset": -480,
        "languages": "zh-CN,zh,en",
        "platform": "Win32",
        "do_not_track": "1",
        "cookie_enabled": True,
        "webrtc_local_ips": ["192.168.31.23"],
        "webrtc_public_ips": ["203.0.113.10"],
        "composite_hash": "comp-high-001",
        "dns_resolver_ip": "223.5.5.5",
        "keystroke": ks(95, 5.2),
        "mouse": ms(1470, 0.24),
        "session_id": "manual-high-a",
        "session_start_at": 1733600400,
        "session_end_at": 1733601000,
    }

    payload_b = dict(payload_a)
    payload_b["session_id"] = "manual-high-b"
    payload_b["session_start_at"] = 1733602400
    payload_b["session_end_at"] = 1733603000
    payload_b["keystroke"] = ks(97, 5.0)
    payload_b["mouse"] = ms(1450, 0.23)

    payload_c = {
        "local_device_id": "dev-mid-001",
        "persistent_id": "",
        "id_source": "",
        "etag_id": "",
        "canvas_hash": "canvas-mid-001",
        "webgl_hash": "webgl-mid-001",
        "webgl_deep_hash": "webgl-deep-mid-001",
        "client_rects_hash": "rects-mid-001",
        "media_devices_hash": "media-mid-001",
        "media_device_group_hash": "media-group-mid-001",
        "media_device_count": "3-1-1",
        "media_device_total": 5,
        "speech_voices_hash": "speech-mid-001",
        "speech_voice_count": 7,
        "speech_local_voice_count": 2,
        "audio_hash": "audio-mid-001",
        "fonts_hash": "fonts-mid-001",
        "fonts_list": "Arial,Helvetica,Times New Roman",
        "screen_width": 1512,
        "screen_height": 982,
        "color_depth": 24,
        "pixel_ratio": 2.0,
        "cpu_cores": 8,
        "device_memory": 8.0,
        "max_touch": 0,
        "timezone": "Asia/Shanghai",
        "tz_offset": -480,
        "languages": "zh-CN,en",
        "platform": "MacIntel",
        "do_not_track": "1",
        "cookie_enabled": True,
        "webrtc_local_ips": ["192.168.77.88"],
        "webrtc_public_ips": ["203.0.113.10"],
        "composite_hash": "comp-mid-001",
        "dns_resolver_ip": "223.5.5.5",
        "keystroke": ks(99, 4.9),
        "mouse": ms(1500, 0.25),
        "session_id": "manual-mid-c",
        "session_start_at": 1733610000,
        "session_end_at": 1733610600,
    }

    payload_d = {
        "local_device_id": "dev-low-001",
        "persistent_id": "",
        "id_source": "",
        "etag_id": "",
        "canvas_hash": "canvas-low-001",
        "webgl_hash": "webgl-low-001",
        "webgl_deep_hash": "webgl-deep-low-001",
        "client_rects_hash": "rects-low-001",
        "media_devices_hash": "media-low-001",
        "media_device_group_hash": "media-group-low-001",
        "media_device_count": "1-0-0",
        "media_device_total": 1,
        "speech_voices_hash": "speech-low-001",
        "speech_voice_count": 4,
        "speech_local_voice_count": 1,
        "audio_hash": "audio-low-001",
        "fonts_hash": "fonts-low-001",
        "fonts_list": "SF Pro,Menlo,Monaco",
        "screen_width": 1536,
        "screen_height": 864,
        "color_depth": 24,
        "pixel_ratio": 2.0,
        "cpu_cores": 4,
        "device_memory": 4.0,
        "max_touch": 0,
        "timezone": "Europe/London",
        "tz_offset": 0,
        "languages": "en-US,en",
        "platform": "MacIntel",
        "do_not_track": "unspecified",
        "cookie_enabled": True,
        "webrtc_local_ips": ["10.8.0.20"],
        "webrtc_public_ips": ["198.51.100.200"],
        "composite_hash": "comp-low-001",
        "dns_resolver_ip": "1.1.1.1",
        "keystroke": {
            "avgHoldTime": 165,
            "stdHoldTime": 44,
            "avgFlightTime": 210,
            "stdFlightTime": 66,
            "typingSpeed": 2.2,
            "sampleCount": 140,
            "commonDigraphs": [
                {
                    "digraph": "digit->digit",
                    "avgFlightTime": 218,
                    "stdFlightTime": 62,
                    "sampleCount": 37,
                },
                {
                    "digraph": "other->alpha",
                    "avgFlightTime": 232,
                    "stdFlightTime": 75,
                    "sampleCount": 21,
                },
            ],
        },
        "mouse": {
            "avgSpeed": 700,
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
        "session_id": "manual-low-d",
        "session_start_at": 1733620000,
        "session_end_at": 1733620900,
    }

    return payload_a, payload_b, payload_c, payload_d


def main() -> None:
    load_dotenv(".env")

    base_url = os.getenv("TEST_BASE_URL", "http://localhost:3001").rstrip("/")
    tokens = [
        os.getenv("TEST_TOKEN_1", ""),
        os.getenv("TEST_TOKEN_2", ""),
        os.getenv("TEST_TOKEN_3", ""),
        os.getenv("TEST_TOKEN_4", ""),
    ]
    users = [
        int(os.getenv("TEST_USER_ID_1", "0")),
        int(os.getenv("TEST_USER_ID_2", "0")),
        int(os.getenv("TEST_USER_ID_3", "0")),
        int(os.getenv("TEST_USER_ID_4", "0")),
    ]
    admin_token = os.getenv("TEST_ADMIN_TOKEN", "")
    admin_id = int(os.getenv("TEST_ADMIN_ID", "1"))

    if not all(tokens) or not admin_token or not all(users):
        raise SystemExit("缺少 tests/fingerprint/.env 凭据配置")

    reporter = FingerprintReporter(base_url)

    for uid in users:
        result = reporter.reset_user_test_data(uid, admin_token, admin_id=admin_id)
        print("reset", uid, result.get("success", False), result.get("message", ""))

    ua_chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ua_safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"

    payload_a, payload_b, payload_c, payload_d = build_payloads()

    profile_a = make_profile(payload_a, "203.0.113.10", ua_chrome)
    profile_b = make_profile(payload_b, "203.0.113.10", ua_chrome)
    profile_c = make_profile(payload_c, "203.0.113.77", ua_safari)
    profile_d = make_profile(payload_d, "192.0.2.99", ua_safari, "en-US,en;q=0.9")

    print("report", users[0], reporter.report(profile_a, tokens[0], users[0]))
    print("report", users[1], reporter.report(profile_b, tokens[1], users[1]))
    print("report", users[2], reporter.report(profile_c, tokens[2], users[2]))
    print("report", users[3], reporter.report(profile_d, tokens[3], users[3]))

    pairs = [
        (users[0], users[1], "HIGH A-B"),
        (users[0], users[2], "MEDIUM A-C"),
        (users[1], users[3], "LOW B-D"),
    ]

    for user_a, user_b, label in pairs:
        data = reporter.wait_for_link(user_a, user_b, admin_token, admin_id=admin_id, timeout=12, poll=0.5) or {}
        print(
            label,
            {
                "pair": [user_a, user_b],
                "confidence": data.get("confidence", 0),
                "tier": data.get("tier", ""),
                "matched_dimensions": data.get("matched_dimensions", []),
            },
        )


if __name__ == "__main__":
    main()
