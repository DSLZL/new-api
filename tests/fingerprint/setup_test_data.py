#!/usr/bin/env python3
"""
一次性初始化脚本:
1. 查看现有 Token
2. 若用户/Token 不足，通过 API 创建（需要 admin token）
3. 生成 .env 文件
"""
import sqlite3
import secrets
import time
import sys

DB_PATH = "one-api.db"

def main():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # 查现有用户
    cur.execute("SELECT id, username, role, status FROM users WHERE deleted_at IS NULL ORDER BY id")
    users = cur.fetchall()
    print("=== 现有用户 ===")
    for u in users:
        print(f"  id={u[0]} username={u[1]} role={u[2]} status={u[3]}")

    # 查现有 Token
    cur.execute("""
        SELECT t.id, t.user_id, u.username, t.key, t.name, t.status
        FROM tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.deleted_at IS NULL AND t.status = 1
        ORDER BY t.user_id, t.id
    """)
    tokens = cur.fetchall()
    print("\n=== 现有 Token ===")
    for t in tokens:
        print(f"  token_id={t[0]} user_id={t[1]} username={t[2]} key=sk-{t[3]} name={t[4]}")

    # 按 user_id 分组，找出每个用户的 token
    user_tokens = {}
    for t in tokens:
        uid = t[1]
        if uid not in user_tokens:
            user_tokens[uid] = f"sk-{t[3]}"

    # 找出 admin (role=100) 和普通用户
    admin_token = None
    normal_tokens = []

    for u in users:
        uid, uname, role, status = u
        if status != 1:
            continue
        tok = user_tokens.get(uid)
        if tok:
            if role >= 100:
                admin_token = tok
            else:
                normal_tokens.append((uid, uname, tok))

    print(f"\n管理员Token: {admin_token}")
    print(f"普通用户Token数量: {len(normal_tokens)}")
    for uid, uname, tok in normal_tokens:
        print(f"  user_id={uid} username={uname} token={tok}")

    # 如果普通用户 Token 不足 4 个，在数据库中直接插入 Token（不创建新用户）
    needed = 4 - len(normal_tokens)
    if needed > 0:
        print(f"\n需要为现有用户补充 {needed} 个 Token...")
        # 找到没有 token 的普通用户，或为已有用户创建新 token
        cur.execute("""
            SELECT id, username FROM users
            WHERE deleted_at IS NULL AND status=1 AND role < 100
        """)
        all_normal = cur.fetchall()
        for uid, uname in all_normal:
            if uid in user_tokens:
                continue
            if needed <= 0:
                break
            raw_key = secrets.token_urlsafe(36)[:48]
            now = int(time.time())
            cur.execute("""
                INSERT INTO tokens
                (user_id, key, status, name, created_time, accessed_time,
                 expired_time, remain_quota, unlimited_quota, model_limits_enabled,
                 model_limits, allow_ips, used_quota, cross_group_retry)
                VALUES (?,?,1,'fp-test',?,?,-1,0,1,0,'','',0,0)
            """, (uid, raw_key, now, now))
            normal_tokens.append((uid, uname, f"sk-{raw_key}"))
            user_tokens[uid] = f"sk-{raw_key}"
            needed -= 1
            print(f"  已为 {uname}(id={uid}) 创建 Token: sk-{raw_key}")

        # 若普通用户数量本身不足 4，提示
        if needed > 0:
            print(f"\n[WARNING] 普通用户数量不足，还差 {needed} 个，请手动注册账号后重跑此脚本")

    # 如果没有 admin token
    if not admin_token:
        cur.execute("SELECT id FROM users WHERE role >= 100 AND deleted_at IS NULL AND status=1 LIMIT 1")
        row = cur.fetchone()
        if row:
            admin_uid = row[0]
            raw_key = secrets.token_urlsafe(36)[:48]
            now = int(time.time())
            cur.execute("""
                INSERT INTO tokens
                (user_id, key, status, name, created_time, accessed_time,
                 expired_time, remain_quota, unlimited_quota, model_limits_enabled,
                 model_limits, allow_ips, used_quota, cross_group_retry)
                VALUES (?,?,1,'fp-admin-test',?,?,-1,0,1,0,'','',0,0)
            """, (admin_uid, raw_key, now, now))
            admin_token = f"sk-{raw_key}"
            print(f"\n已为管理员(id={admin_uid})创建 Token: {admin_token}")

    con.commit()
    con.close()

    # 写 .env
    if len(normal_tokens) < 4 or not admin_token:
        print("\n[ERROR] Token 不足，无法生成 .env，请先补充用户")
        sys.exit(1)

    env_lines = [
        "TEST_BASE_URL=http://localhost:3000",
        f"TEST_TOKEN_1={normal_tokens[0][2]}",
        f"TEST_TOKEN_2={normal_tokens[1][2]}",
        f"TEST_TOKEN_3={normal_tokens[2][2]}",
        f"TEST_TOKEN_4={normal_tokens[3][2]}",
        f"TEST_ADMIN_TOKEN={admin_token}",
    ]
    env_content = "\n".join(env_lines) + "\n"
    with open("tests/fingerprint/.env", "w") as f:
        f.write(env_content)

    print("\n=== 生成 .env ===")
    print(env_content)
    print(".env 写入完成！")


if __name__ == "__main__":
    main()
