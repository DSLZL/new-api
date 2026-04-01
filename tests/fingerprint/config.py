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

# ── 各场景预期置信度阈值 ──────────────────────────────────────────────
THRESHOLDS = {
    # 场景A: 同设备两账号 → 强关联
    "scenario_a": {"min": 0.80, "desc": "同设备双账号（相同Canvas/WebGL/LocalDeviceID）"},
    # 场景B: 同设备换VPN → 设备哈希仍能关联
    "scenario_b": {"min": 0.65, "desc": "同设备VPN换IP（相同Canvas/WebGL）"},
    # 场景C: 无痕模式，共享IP → IP关联
    "scenario_c": {"min": 0.35, "desc": "无痕模式共享IP（无Canvas/LocalDevice）"},
    # 场景D: 完全不同设备 → 不应关联
    "scenario_d": {"max": 0.30, "desc": "完全不同设备和网络"},
}

# ── 模拟IP（直接写入 X-Real-IP）─────────────────────────────────────
SIM_IPS = {
    "home":       "203.0.113.10",     # 用户A/B/C的家庭IP
    "vpn":        "198.51.100.42",    # 用户C的VPN出口IP
    "incognito":  "203.0.113.10",     # 用户D：无痕但同IP
    "stranger":   "192.0.2.99",       # 用户E：完全不同IP
}
