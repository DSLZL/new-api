import sqlite3
conn = sqlite3.connect('C:/Users/Long/Desktop/folder/Code/new-api/one-api.db')
print('=== 用户列表 ===')
for row in conn.execute('SELECT id, username, role FROM users ORDER BY id').fetchall():
    print(row)
print()
print('=== 最新指纹 ===')
for row in conn.execute('SELECT user_id, canvas_hash, webgl_hash, local_device_id, ip_address, created_at FROM user_fingerprints ORDER BY created_at DESC LIMIT 15').fetchall():
    uid, canvas, webgl, did, ip, ts = row
    print(f'user={uid} canvas={canvas[:16] if canvas else "EMPTY"} webgl={webgl[:16] if webgl else "EMPTY"} did={did[:12] if did else "EMPTY"} ip={ip} t={str(ts)[-15:]}')
