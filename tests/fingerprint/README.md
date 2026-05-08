# 指纹识别系统集成测试

使用 [browserforge](https://github.com/daijro/browserforge) 生成真实浏览器指纹，通过 HTTP 向 new-api 的指纹上报接口发送数据，验证关联检测算法的准确性。

## 场景说明

| 场景 | 模拟行为 | 期望置信度 |
|------|----------|------------|
| A | 同设备两个账号（相同 Canvas/WebGL/LocalDeviceID/IP） | ≥ 80% |
| B | 同设备换 VPN（相同设备哈希，不同 IP） | ≥ 65% |
| C | 无痕模式（无 Canvas/LocalDeviceID，共享 IP） | ≥ 35% |
| D | 完全不同设备和网络（负例，不应关联） | ≤ 30% |

## 快速开始

### 1. 安装依赖

```bash
cd tests/fingerprint
pip install -r requirements.txt
```

### 2. 配置 Token

```bash
cp .env.example .env
# 编辑 .env，填写以下字段
```

需要的 Token：

- `TEST_BASE_URL` — new-api 服务地址（默认 `http://localhost:3000`）  
- `TEST_TOKEN_1` ~ `TEST_TOKEN_4` — 4 个**不同**普通用户的 Token（在用户设置页生成 API Key 后填入）  
- `TEST_ADMIN_TOKEN` — 管理员 Token（用于查询关联结果）

> Token 格式：直接填 Token 字符串即可，脚本会自动加 `Bearer ` 前缀。

### 3. 确认 new-api 已启用指纹系统

管理员后台 → 系统设置 → 启用指纹识别 = true

### 4. 运行测试

```bash
python test_runner.py
```

## 输出示例

```
━━━━━━━━━━━━ 场景 A: 同设备双账号 ━━━━━━━━━━━━
  上报 [账号A1 - 主账号] → OK
  上报 [账号A2 - 同设备小号] → OK
  等待关联分析...
  置信度: 92.3%  维度匹配: 6/9  共享IP: 1  结果: PASS

┌──────┬────────────────────────────────┬──────────┬──────────┬────────┐
│ 场景 │ 说明                           │  置信度  │ 期望     │ 结果   │
├──────┼────────────────────────────────┼──────────┼──────────┼────────┤
│ A    │ 同设备双账号（相同Canvas/…）   │   92.3%  │ >= 80%   │  PASS  │
│ B    │ 同设备VPN换IP（相同Canvas/…）  │   78.1%  │ >= 65%   │  PASS  │
│ C    │ 无痕模式共享IP                 │   48.0%  │ >= 35%   │  PASS  │
│ D    │ 完全不同设备和网络             │   12.5%  │ <= 30%   │  PASS  │
└──────┴────────────────────────────────┴──────────┴──────────┴────────┘
最终结果: 全部通过
```

## 工作原理

```
test_runner.py
    │
    ├── FingerprintScenarios.scenario_a/b/c/d()
    │       └── 用 browserforge 生成真实 UA/Headers
    │           注入固定/随机的 canvas_hash, webgl_hash, local_device_id 等
    │
    ├── FingerprintReporter.report(profile, token)
    │       POST /api/fingerprint/report
    │       X-Real-IP: <模拟IP>    ← 服务端 ExtractRealIP 优先读此头
    │
    └── FingerprintReporter.wait_for_link(uid_a, uid_b, admin_token)
            POST /api/admin/fingerprint/compare
            轮询直到返回 confidence 字段（最多 15 秒）
```

## 文件结构

```
tests/fingerprint/
├── config.py                 # 服务地址、Token、阈值配置
├── fingerprint_generator.py  # browserforge 指纹生成 + 4 个场景
├── reporter.py               # HTTP 客户端（上报 + 查询）
├── test_runner.py            # 测试主程序
├── requirements.txt
├── .env.example
└── README.md
```

## 注意事项

- 场景 A/B 复用 `TEST_TOKEN_1`，场景 B 用 `TEST_TOKEN_3`，场景 C 用 `TEST_TOKEN_4`  
  确保这 4 个账号属于**不同**真实用户，且在测试前**没有**共同指纹历史  
- `X-Real-IP` 头只在没有反向代理的本地测试环境有效；  
  若 new-api 前有 Nginx/Caddy，请确认代理不覆盖该头部，或改用 `CF-Connecting-IP`  
- 场景 D 先于汇总输出之前上报