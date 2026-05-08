"""测试配置 - 修改此处再运行"""
import os

# ── 服务地址 ──────────────────────────────────────────────────────────
BASE_URL = os.getenv("TEST_BASE_URL", "http://localhost:3000")

# ── 测试账号 Token（access_token，对应 users.access_token 字段）──────
USER_TOKENS = [
    os.getenv("TEST_TOKEN_1", ""),
    os.getenv("TEST_TOKEN_2", ""),
    os.getenv("TEST_TOKEN_3", ""),
    os.getenv("TEST_TOKEN_4", ""),
]

# ── 测试账号对应的用户 ID（认证需同时提供 New-Api-User 头）────────────
USER_IDS = [
    int(os.getenv("TEST_USER_ID_1", "4")),
    int(os.getenv("TEST_USER_ID_2", "5")),
    int(os.getenv("TEST_USER_ID_3", "6")),
    int(os.getenv("TEST_USER_ID_4", "7")),
]

# ── 管理员 Token 和 ID（用于查询关联结果）────────────────────────────
ADMIN_TOKEN = os.getenv("TEST_ADMIN_TOKEN", "")
ADMIN_ID    = int(os.getenv("TEST_ADMIN_ID", "1"))

# ── 各场景预期置信度阈值（Final 六类）────────────────────────────────
THRESHOLDS = {
    # 场景1: 同设备高分
    "scenario_1_same_device_high": {
        "min": 0.80,
        "desc": "同设备 + 同浏览器 + 不同账号，预期高分",
    },
    # 场景2: 隐身中高分（靠 JA4 + 行为）
    "scenario_2_incognito_medium_high": {
        "min": 0.55,
        "desc": "同设备隐身模式，预期中高分（JA4 + 行为）",
    },
    # 场景3: VPN中高分（靠 WebRTC + 设备指纹）
    "scenario_3_vpn_medium_high": {
        "min": 0.60,
        "desc": "同设备 VPN 切换 IP，预期中高分（WebRTC + 设备指纹）",
    },
    # 场景4: 清缓存中高分（靠 ETag + 设备指纹）
    "scenario_4_clear_cache_medium_high": {
        "min": 0.60,
        "desc": "同设备清缓存后，预期中高分（ETag + 设备指纹）",
    },
    # 场景5: 不同设备同一人中分（靠行为 + 时序）
    "scenario_5_same_person_diff_device_medium": {
        "min": 0.35,
        "desc": "不同设备同一人，预期中分（行为 + 时序）",
    },
    # 场景6: 完全不同低分
    "scenario_6_completely_different_low": {
        "max": 0.30,
        "desc": "完全不同用户，预期低分",
    },
}

# ── 模拟IP（直接写入 X-Real-IP）─────────────────────────────────────
SIM_IPS = {
    "home": "203.0.113.10",
    "vpn": "198.51.100.42",
    "alt_home": "203.0.113.77",
    "stranger": "192.0.2.99",
}
