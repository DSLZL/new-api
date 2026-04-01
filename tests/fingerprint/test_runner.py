#!/usr/bin/env python3
"""
test_runner.py - 指纹识别系统集成测试

用法:
  1. 复制 .env.example 为 .env 并填写 Token
  2. pip install -r requirements.txt
  3. python test_runner.py

需要:
  - new-api 服务运行中且 FingerprintEnabled = true
  - 4 个普通用户 Token + 1 个管理员 Token
"""
import sys
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.table import Table
from rich import box

from config import BASE_URL, USER_TOKENS, USER_IDS, ADMIN_TOKEN, ADMIN_ID, THRESHOLDS, SIM_IPS
from fingerprint_generator import FingerprintScenarios, BROWSERFORGE_OK
from reporter import FingerprintReporter

console = Console()
reporter = FingerprintReporter(BASE_URL)
scenarios = FingerprintScenarios()


# ──────────────────────────────────────────────────────────────────────
# 辅助函数
# ──────────────────────────────────────────────────────────────────────

def _token(index: int) -> str:
    t = USER_TOKENS[index]
    if not t:
        console.print(f"[red]错误: TEST_TOKEN_{index+1} 未配置[/red]")
        sys.exit(1)
    return t  # access_token 直接用，不加 Bearer


def _uid(index: int) -> int:
    return USER_IDS[index]


def _admin() -> str:
    if not ADMIN_TOKEN:
        console.print("[red]错误: TEST_ADMIN_TOKEN 未配置[/red]")
        sys.exit(1)
    return ADMIN_TOKEN


def _get_uid(index: int) -> int:
    """直接从 USER_IDS 获取用户 ID（已写入 .env）"""
    return USER_IDS[index]


def _report(profile, token_index: int, delay: float = 0.3) -> bool:
    """上报单条指纹，打印结果"""
    time.sleep(delay)
    result = reporter.report(profile, _token(token_index), _uid(token_index))
    ok = result.get("success", False)
    tag = "[green]OK[/green]" if ok else f"[red]FAIL: {result.get('message','?')}[/red]"
    console.print(f"  上报 [{profile.label}] → {tag}")
    return ok


def _check(confidence: float, key: str) -> tuple[bool, str]:
    cfg = THRESHOLDS[key]
    if "min" in cfg:
        return confidence >= cfg["min"], f">= {cfg['min']:.0%}"
    return confidence <= cfg["max"], f"<= {cfg['max']:.0%}"


def _fmt(scenario: str, uid_a: int, uid_b: int, data: dict | None, key: str) -> dict:
    if data is None:
        confidence = 0.0
        matched = 0
        total = 0
        shared_ips = []
    else:
        confidence = data.get("confidence", 0.0)
        matched = data.get("match_dimensions", 0)
        total = data.get("total_dimensions", 0)
        shared_ips = data.get("shared_ips") or []

    passed, expected = _check(confidence, key)

    console.print(
        f"  置信度: [bold]{confidence:.1%}[/bold]  "
        f"维度匹配: {matched}/{total}  "
        f"共享IP: {len(shared_ips)}  "
        f"结果: {'[green]PASS[/green]' if passed else '[red]FAIL[/red]'}"
    )
    return {
        "scenario": scenario,
        "uid_a": uid_a,
        "uid_b": uid_b,
        "confidence": confidence,
        "expected": expected,
        "passed": passed,
        "shared_ips": shared_ips,
    }


# ──────────────────────────────────────────────────────────────────────
# 测试场景
# ──────────────────────────────────────────────────────────────────────

def run_scenario_a() -> dict:
    """场景A: 同设备双账号 → 预期 confidence >= 0.80"""
    console.rule("[bold cyan]场景 A: 同设备双账号[/bold cyan]")
    console.print(f"  {THRESHOLDS['scenario_a']['desc']}")

    profiles = scenarios.scenario_a(sim_ip=SIM_IPS["home"])
    uid_a, uid_b = _get_uid(0), _get_uid(1)
    console.print(f"  用户A: {uid_a}  用户B: {uid_b}")

    _report(profiles[0], 0)
    _report(profiles[1], 1)

    console.print("  等待关联分析...")
    data = reporter.wait_for_link(uid_a, uid_b, _admin(), admin_id=ADMIN_ID)
    return _fmt("A", uid_a, uid_b, data, "scenario_a")


def run_scenario_b() -> dict:
    """场景B: VPN 换IP，Canvas/WebGL 相同 → 预期 confidence >= 0.65"""
    console.rule("[bold cyan]场景 B: VPN 换 IP[/bold cyan]")
    console.print(f"  {THRESHOLDS['scenario_b']['desc']}")

    profiles = scenarios.scenario_b(
        ip_normal=SIM_IPS["home"],
        ip_vpn=SIM_IPS["vpn"],
    )
    uid_a, uid_b = _get_uid(0), _get_uid(2)
    console.print(f"  用户A: {uid_a}  用户C: {uid_b}")

    _report(profiles[0], 0)
    _report(profiles[1], 2)

    console.print("  等待关联分析...")
    data = reporter.wait_for_link(uid_a, uid_b, _admin(), admin_id=ADMIN_ID)
    return _fmt("B", uid_a, uid_b, data, "scenario_b")


def run_scenario_c() -> dict:
    """场景C: 无痕模式 + 共享IP → 预期 confidence >= 0.35"""
    console.rule("[bold cyan]场景 C: 无痕模式 + 共享 IP[/bold cyan]")
    console.print(f"  {THRESHOLDS['scenario_c']['desc']}")

    profiles = scenarios.scenario_c(sim_ip=SIM_IPS["home"])
    uid_a, uid_b = _get_uid(0), _get_uid(3)
    console.print(f"  用户A: {uid_a}  用户D: {uid_b}")

    _report(profiles[0], 0)
    _report(profiles[1], 3)

    console.print("  等待关联分析...")
    data = reporter.wait_for_link(uid_a, uid_b, _admin(), admin_id=ADMIN_ID)
    return _fmt("C", uid_a, uid_b, data, "scenario_c")


def _purge_fingerprints_for_users(*user_ids: int) -> None:
    """直接清除指定用户的指纹和关联记录（仅用于测试隔离）"""
    import sqlite3, glob as _glob
    db_path = None
    # 在项目根目录找 .db 文件
    for p in _glob.glob("../../*.db") + _glob.glob("../*.db") + _glob.glob("*.db"):
        db_path = p
        break
    if not db_path:
        console.print("[yellow]警告: 找不到 SQLite DB，跳过清理[/yellow]")
        return
    conn = sqlite3.connect(db_path)
    for uid in user_ids:
        conn.execute("DELETE FROM user_fingerprints WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM account_links WHERE user_id_a = ? OR user_id_b = ?", (uid, uid))
    conn.commit()
    conn.close()
    console.print(f"  [dim]已清除用户 {list(user_ids)} 的历史指纹记录[/dim]")


def run_scenario_d() -> dict:
    """场景D: 完全不同设备 → 预期 confidence <= 0.30"""
    console.rule("[bold cyan]场景 D: 完全不同设备（负例）[/bold cyan]")
    console.print(f"  {THRESHOLDS['scenario_d']['desc']}")

    uid_a, uid_b = _get_uid(0), _get_uid(1)
    console.print(f"  用户A: {uid_a}  用户B: {uid_b}")

    # 清除场景A留下的历史关联，保证测试隔离
    _purge_fingerprints_for_users(uid_a, uid_b)

    profiles = scenarios.scenario_d(
        ip_x=SIM_IPS["home"],
        ip_y=SIM_IPS["stranger"],
    )

    _report(profiles[0], 0)
    _report(profiles[1], 1)

    # 等待短暂让后台处理
    time.sleep(2)
    data = reporter.compare(uid_a, uid_b, _admin(), admin_id=ADMIN_ID)
    return _fmt("D", uid_a, uid_b, data, "scenario_d")


# ──────────────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────────────

def preflight() -> None:
    """启动前检查"""
    if not BROWSERFORGE_OK:
        console.print("[yellow]警告: browserforge 未安装，使用内置 User-Agent 回退[/yellow]")
    if not all(USER_TOKENS):
        console.print("[red]错误: 请在 .env 中配置全部 4 个 TEST_TOKEN_*[/red]")
        sys.exit(1)
    if not ADMIN_TOKEN:
        console.print("[red]错误: 请配置 TEST_ADMIN_TOKEN[/red]")
        sys.exit(1)

    # 验证服务可达
    import requests as _req
    try:
        r = _req.get(BASE_URL.rstrip("/") + "/api/status", timeout=5, verify=False)
        if r.status_code != 200:
            console.print(f"[red]错误: 服务返回 {r.status_code}，请确认 new-api 已启动[/red]")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]错误: 无法连接到 {BASE_URL} — {e}[/red]")
        sys.exit(1)

    console.print(f"[green]OK 服务可达: {BASE_URL}[/green]")


def main() -> None:
    seed_only = '--seed-only' in sys.argv

    console.print()
    console.rule("[bold magenta]new-api 指纹识别系统集成测试[/bold magenta]")
    console.print(f"  目标服务: [bold]{BASE_URL}[/bold]")
    if seed_only:
        console.print("  模式: [yellow]仅填充数据（--seed-only），跳过场景D[/yellow]")
    console.print()

    preflight()

    results = []
    results.append(run_scenario_a())
    results.append(run_scenario_b())
    results.append(run_scenario_c())
    if not seed_only:
        results.append(run_scenario_d())

    # ── 汇总表 ──
    console.print()
    console.rule("[bold]测试汇总[/bold]")
    tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
    tbl.add_column("场景",   width=6)
    tbl.add_column("说明",   width=32)
    tbl.add_column("置信度", justify="right", width=10)
    tbl.add_column("期望",   width=12)
    tbl.add_column("结果",   justify="center", width=8)

    all_pass = True
    for r in results:
        key  = f"scenario_{r['scenario'].lower()}"
        desc = THRESHOLDS[key]["desc"]
        color = "green" if r["passed"] else "red"
        icon  = "PASS"  if r["passed"] else "FAIL"
        if not r["passed"]:
            all_pass = False
        tbl.add_row(
            r["scenario"],
            desc,
            f"{r['confidence']:.1%}",
            r["expected"],
            f"[{color}]{icon}[/{color}]",
        )

    console.print(tbl)
    final = "[bold green]全部通过[/bold green]" if all_pass else "[bold red]存在失败[/bold red]"
    console.print(f"\n最终结果: {final}\n")
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
