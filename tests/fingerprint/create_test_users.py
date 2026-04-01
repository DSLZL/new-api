#!/usr/bin/env python3
"""创建额外测试用户并生成完整 .env"""
import sqlite3
import secrets
import time
import bcrypt

DB_PATH = "one-api.db"
PASSWORD = "testpass123"

def make_token_key():
    return secrets.token_urlsafe(36)[:48]

def insert_user(cur, username, display_name):
    pw_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    aff_code = secrets.token_hex(8)
    cur.execute("""
        INSERT OR IGNORE INTO users
        (username, password, display_name, role, status, email,
         quota, used_quota, request_count, `group`, aff_code)
        VALUES (?,?,?,1,1,'',500000,0,0,'default',?)
    """, (username, pw_hash, display_name, aff_code))
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    return cur.fetchone()[0]

def insert_token(cur, user_id, name):
    key = make_token_key()
    now = int(time.time())
    cur.execute("""
        INSERT INTO tokens
        (user_id, key, status, name, created_time, accessed_time,
         expired_time, remain_quota, unlimited_quota, model_limits_enabled,
         model_limits, allow_ips, used_quota, cross_group_retry)
        VALUES (?,?,1,?,?,?,-1,0,1,0,'','',0,0)
    """, (user_id, key, name, now, now))
    return f"sk-{key}"

def main():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    # 确保有 4 个普通用户
    test_users = [
        ("fp_test_user1", "FP测试用户1"),
        ("fp_test_user2", "FP测试用户2"),
        ("fp_test_user3", "FP测试用户3"),
        ("fp_test_user4", "FP测试用户4"),
    ]
    user_ids = []
    for uname, dname in test_users:
        uid = insert_user(cur, uname, dname)
        user_ids.append(uid)
        print(f"用户 {uname} id={uid}")

    # 为每个用户创建 Token
    normal_tokens = []
    for i, uid in enumerate(user_ids):
        tok = insert_token(cur, uid, f"fp-test-{i+1}")
        normal_tokens.append(tok)
        print(f"  Token: {tok}")

    # 管理员 Token (id=1)
    admin_tok = insert_token(cur, 1, "fp-admin-test")
    print(f"管理员 Token: {admin_tok}")

    con.commit()
    con.close()

    # 写 .env
    env = "\n".join([
        "TEST_BASE_URL=http://localhost:3000",
        f"TEST_TOKEN_1={normal_tokens[0]}",
        f"TEST_TOKEN_2={normal_tokens[1]}",
        f"TEST_TOKEN_3={normal_tokens[2]}",
        f"TEST_TOKEN_4={normal_tokens[3]}",
        f"TEST_ADMIN_TOKEN={admin_tok}",
    ]) + "\n"

    with open("tests/fingerprint/.env", "w", encoding="utf-8") as f:
        f.write(env)

    print("\n=== .env 内容 ===")
    print(env)
    print(".env 写入成功！")

if __name__ == "__main__":
    main()
