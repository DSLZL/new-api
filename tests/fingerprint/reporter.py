"""HTTP 客户端 - 向 new-api 上报指纹并查询关联结果"""
import time
import requests
from typing import Optional

from config import BASE_URL
from fingerprint_generator import BrowserProfile


class FingerprintReporter:
    """封装指纹上报和关联查询的 HTTP 操作"""

    REPORT_PATH  = "/api/fingerprint/report"
    COMPARE_PATH = "/api/admin/fingerprint/compare"
    LINKS_PATH   = "/api/admin/fingerprint/links"
    ASSOC_PATH   = "/api/admin/fingerprint/user/{uid}/associations"
    RESET_PATH   = "/api/admin/fingerprint/user/{uid}/reset-test-data"
    SELF_PATH    = "/api/user/self"

    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False  # 本地测试跳过 TLS 验证

    # ──────────────────────────────────────────────────────────────
    # 上报指纹
    # ──────────────────────────────────────────────────────────────

    def report(self, profile: BrowserProfile, token: str, user_id: int = 0) -> dict:
        """
        POST /api/fingerprint/report

        token   : access_token 字符串（不含 Bearer 前缀）
        user_id : 用户 ID，写入 New-Api-User 头（认证必需）
        X-Real-IP 写入模拟 IP，服务端 ExtractRealIP 优先读取该头部
        """
        headers = {
            **profile.headers,
            "Authorization": token,
            "Content-Type":  "application/json",
            "X-Real-IP":     profile.sim_ip,
            "New-Api-User":  str(user_id),
        }
        try:
            resp = self.session.post(
                self.base_url + self.REPORT_PATH,
                json=profile.payload,
                headers=headers,
                timeout=10,
            )
            return resp.json()
        except Exception as e:
            return {"success": False, "message": str(e)}

    # ──────────────────────────────────────────────────────────────
    # 查询用户信息
    # ──────────────────────────────────────────────────────────────

    def get_user_id(self, token: str, user_id: int) -> int:
        """通过 GET /api/user/self 获取当前用户 ID"""
        try:
            resp = self.session.get(
                self.base_url + self.SELF_PATH,
                headers={"Authorization": token, "New-Api-User": str(user_id)},
                timeout=5,
            )
            return resp.json().get("data", {}).get("id", 0)
        except Exception:
            return 0

    # ──────────────────────────────────────────────────────────────
    # 关联对比（admin）
    # ──────────────────────────────────────────────────────────────

    def compare(self, user_a: int, user_b: int, admin_token: str, admin_id: int = 1) -> Optional[dict]:
        """
        POST /api/admin/fingerprint/compare

        即时返回两用户的关联置信度（取最近各 5 条指纹的最佳得分）。
        响应 data 字段包含:
          confidence, match_dimensions, total_dimensions, details, shared_ips
        """
        headers = {
            "Authorization": admin_token,
            "Content-Type":  "application/json",
            "New-Api-User":  str(admin_id),
        }
        try:
            resp = self.session.post(
                self.base_url + self.COMPARE_PATH,
                json={"user_a": user_a, "user_b": user_b},
                headers=headers,
                timeout=10,
            )
            body = resp.json()
            if body.get("success"):
                return body.get("data")
            return None
        except Exception:
            return None

    def wait_for_link(
        self,
        user_a: int,
        user_b: int,
        admin_token: str,
        admin_id: int = 1,
        timeout: int = 15,
        poll: float = 0.5,
    ) -> Optional[dict]:
        """
        上报后后台异步运行 AnalyzeAccountLinks，
        轮询 compare 直到拿到有效 confidence 或超时。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.compare(user_a, user_b, admin_token, admin_id)
            if data and "confidence" in data:
                return data
            time.sleep(poll)
        return self.compare(user_a, user_b, admin_token, admin_id)

    # ──────────────────────────────────────────────────────────────
    # 查询某用户所有关联（admin）
    # ──────────────────────────────────────────────────────────────

    def get_associations(
        self,
        uid: int,
        admin_token: str,
        min_confidence: float = 0.0,
    ) -> Optional[dict]:
        """
        GET /api/admin/fingerprint/user/:id/associations
        返回该用户与其他账号的全部关联，按置信度排序。
        """
        headers = {"Authorization": admin_token}
        try:
            resp = self.session.get(
                self.base_url + self.ASSOC_PATH.format(uid=uid),
                headers=headers,
                params={"min_confidence": min_confidence, "limit": 20},
                timeout=10,
            )
            body = resp.json()
            if body.get("success"):
                return body.get("data")
            return None
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────
    # 查询待审核关联列表（admin）
    # ──────────────────────────────────────────────────────────────

    def get_pending_links(
        self,
        admin_token: str,
        min_confidence: float = 0.3,
        page: int = 1,
    ) -> Optional[dict]:
        """GET /api/admin/fingerprint/links?status=pending"""
        headers = {"Authorization": admin_token}
        try:
            resp = self.session.get(
                self.base_url + self.LINKS_PATH,
                headers=headers,
                params={
                    "status":         "pending",
                    "min_confidence": min_confidence,
                    "page":           page,
                    "page_size":      50,
                },
                timeout=10,
            )
            return resp.json()
        except Exception as e:
            return {"success": False, "message": str(e)}

    def reset_user_test_data(self, uid: int, admin_token: str, admin_id: int = 1) -> dict:
        """POST /api/admin/fingerprint/user/:id/reset-test-data"""
        headers = {
            "Authorization": admin_token,
            "Content-Type":  "application/json",
            "New-Api-User":  str(admin_id),
        }
        try:
            resp = self.session.post(
                self.base_url + self.RESET_PATH.format(uid=uid),
                headers=headers,
                timeout=10,
            )
            return resp.json()
        except Exception as e:
            return {"success": False, "message": str(e)}
