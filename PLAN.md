# plan.md — 多账户关联检测系统增强实施计划

> **目标**：在现有指纹系统基础上，新增 14 个检测维度，覆盖「隐身模式 / 清除缓存 / VPN」三大规避盲区。  
> **原则**：按 P0 → P1 → P2 → P3 分阶段交付，每阶段可独立上线。

---

## 阶段总览

| 阶段 | 内容 | 涉及文件数 | 预期效果 |
|------|------|-----------|---------|
| **P0** | TLS/JA4 · 多存储持久化+ETag · WebRTC IP泄露（核心已完成） | ~18 | 堵住三大规避盲区 |
| **P1** | WebGL深度 · ClientRects · HTTP Header指纹 · MediaDevices · SpeechVoices | ~10 | 设备指纹维度翻倍 |
| **P2** | ASN/ISP · DNS泄露 · 登录时间模式 · 会话互斥分析 | ~8 | 网络+时序关联 |
| **P3** | 打字节奏 · 鼠标行为（核心链路已完成） | ~8 | 生物特征级识别 |
| **Final** | 分层评分算法重构 · 权重表更新 · 管理后台可视化 | ~10 | 整合所有维度 |

---

## Phase 0 — P0：堵住三大盲区

### Task 0.1：TLS/JA4 指纹（服务端被动采集）

**原理**：TLS ClientHello 中的密码套件顺序、扩展列表等构成唯一签名，用户 JS 层面完全无法干预，即使用代理/VPN 指纹也不变。

#### 0.1.1 JA4 采集（已按方案 C 落地）

- [x] **完成** Go 应用层 TLS 回调采集（方案 C）
  - 方案 A（推荐）：使用 OpenResty + `lua-resty-ja4` 在 Nginx 层提取 JA4，写入请求头 `X-JA4-Fingerprint`
  - 方案 B：若使用 Caddy/Traefik，用 Go 中间件在 TLS 层 hook `ClientHelloInfo` 提取
  - 方案 C：若无法改反代，在 Go 应用层用 `crypto/tls` 的 `GetConfigForClient` 回调提取（本次已实现）
  - 计算好的 JA4 哈希值可通过 HTTP Header `X-JA4-Fingerprint` 传给后端（兼容保留）

> 进度备注：已完成方案 C（Go 应用层 TLS 回调提取 JA4），并保留 `X-JA4-Fingerprint` 兼容读取路径。

```
# OpenResty 示例思路
# 在 ssl_certificate_by_lua_block 中:
#   1. 获取 SSL 对象
#   2. 提取 cipher suites / extensions / supported groups / signature algorithms
#   3. 按 JA4 规范拼接并哈希
#   4. 存入 ngx.ctx，后续 header_filter 阶段写入 X-JA4-Fingerprint
```

#### 0.1.2 后端读取与存储

- [x] **修改** `middleware/fingerprint_collect.go`
  - 在现有 IP/UA 采集逻辑中，新增读取 `X-JA4-Fingerprint` 请求头
  - 将 JA4 值随指纹数据一起传入后续处理流程
  - 对空值做容错（反代未配置时不影响已有逻辑）

```go
// 在 fingerprint_collect.go 的采集函数中增加：
ja4 := c.GetHeader("X-JA4-Fingerprint")
if ja4 != "" {
    fingerprintData.JA4 = ja4
}
```

- [x] **修改** `model/fingerprint.go`
  - `DeviceFingerprint` 结构体新增 `JA4 string` 字段（`json:"ja4"` / `gorm:"column:ja4;index"`）
  - 确保 JSON 序列化/反序列化兼容

- [x] **修改** `model/fingerprint_migration.go`
  - 新增 `ja4` 列的迁移逻辑（VARCHAR(128) + 索引）
  - 使用 `AutoMigrate` 或手动 `ALTER TABLE` 确保幂等

#### 0.1.3 关联匹配

- [x] **修改** `service/link_analyzer.go`
  - 在相似度计算函数中新增 JA4 精确匹配分支
  - 匹配权重：0.85
  - JA4 相同 + 其他弱信号即可提升关联置信度

```go
// link_analyzer.go 中的相似度计算增加:
if a.JA4 != "" && a.JA4 == b.JA4 {
    score += 0.85 * weights.JA4
}
```

---

### Task 0.2：多存储持久化 + ETag 追踪

**原理**：在 localStorage / IndexedDB / Cache API / Cookie / ETag 等多个位置存储追踪 ID，用户很难全部清除。ETag 基于 HTTP 缓存机制，清 Cookie 也无法消除。

#### 0.2.1 前端多存储持久化

- [x] **修改** `web/src/utils/fingerprint.js`
  - 新增 `PersistentTracker` 类，实现 `setEverywhere()` 和 `getFromAnywhere()` 方法
  - 存储位置（按可靠性排序）：
    1. `localStorage` — `_fp_sid`
    2. `IndexedDB` — 数据库 `_fpDB`，对象仓库 `store`，键 `sid`
    3. `Cookie` — `_fp_sid`，`max-age=31536000; path=/; secure; samesite=lax`
    4. `Cache API` — 缓存名 `_fp_track`，键 `/_fp_track_id`
    5. `sessionStorage` — `_fp_sid`（同标签页生命周期内的补充）
  - `getFromAnywhere()` 从所有来源读取，返回第一个有效值
  - 当任一来源有值但其他来源缺失时，自动回填所有来源（自愈机制）
  - 所有操作用 try-catch 包裹，任何单一存储失败不影响整体

```javascript
// fingerprint.js 新增:
class PersistentTracker {
    constructor(trackingId) { this.id = trackingId; }
    
    async setEverywhere() { /* 5 个存储位置 */ }
    async getFromAnywhere() { /* 返回 {source, id}[] */ }
    async selfHeal(validId) { /* 用有效ID回填缺失存储 */ }
}
```

- [x] **修改** `web/src/hooks/useFingerprint.js`
  - 在指纹上报 Hook 中集成 `PersistentTracker`
  - 流程：先 `getFromAnywhere()` 尝试恢复旧 ID → 若无则生成新 ID → `setEverywhere()` 存储 → 上报时携带 `persistentId` 字段和 `idSource`（标记从哪个存储恢复的）

#### 0.2.2 ETag 追踪端点

- [x] **新建** `controller/etag_tracker.go`
  - 实现 `GET /api/static/fp.js` 端点
  - 逻辑：
    - 检查请求头 `If-None-Match`
    - 若存在：提取 ETag 值作为 `trackingId`，记录到数据库，返回 `304 Not Modified`
    - 若不存在：生成 `uuid` 作为新 `trackingId`，返回一段无害 JS，设置 `ETag: "<trackingId>"`，`Cache-Control: private, max-age=31536000`
  - 关联逻辑：将 ETag ID 与当前登录用户/指纹绑定

```go
// etag_tracker.go 核心逻辑:
func ETagTracker(c *gin.Context) {
    etag := c.GetHeader("If-None-Match")
    if etag != "" {
        trackingId := strings.Trim(etag, "\"")
        recordETagVisit(c, trackingId) // 异步记录
        c.Header("ETag", etag)
        c.Status(304)
        return
    }
    trackingId := uuid.New().String()
    c.Header("ETag", fmt.Sprintf(`"%s"`, trackingId))
    c.Header("Cache-Control", "private, max-age=31536000")
    c.Data(200, "application/javascript", []byte("/* fp */"))
}
```

- [x] **修改** `router/api-router.go`
  - 注册 `GET /api/static/fp.js` 路由，绑定 `ETagTracker` 处理器
  - 此路由**不走**常规鉴权中间件（需要未登录状态也能追踪）

- [x] **修改** `model/fingerprint.go`
  - 新增 `ETagID string` 字段
  - 或新建关联表 `etag_tracking (etag_id, user_id, fingerprint_hash, first_seen, last_seen, visit_count)`

- [x] **修改** `model/fingerprint_migration.go`
  - 新增 ETag 相关字段/表的迁移

- [x] **修改** `web/src/utils/fingerprint.js`
  - 在指纹采集流程的**最前面**，插入一个 `<script>` 标签或 `fetch` 请求加载 `/api/static/fp.js`
  - 确保浏览器会携带缓存的 ETag

> 进度备注：ETag 后端端点、路由与落库已完成；前端已接入 `fetch('/api/static/fp.js')` 触发缓存协商。

```javascript
// fingerprint.js 指纹采集入口处:
async function triggerETagTracking() {
    // 用 fetch + cache: 'default' 确保走浏览器缓存 → 自动带 If-None-Match
    await fetch('/api/static/fp.js', { cache: 'default', credentials: 'same-origin' });
}
```

#### 0.2.3 后端关联

- [x] **修改** `service/link_analyzer.go`
  - 新增 ETag ID 匹配逻辑，权重 0.80
  - 新增 PersistentID 匹配逻辑，权重 0.95（恢复的追踪 ID 等于强标识）
  - 在「一票通过」层处理这两个匹配

> 进度备注：ETag/PersistentID 匹配与权重已实现，且已完成“一票通过命中后直接返回”的分层短路。

---

### Task 0.3：WebRTC 本地 IP 泄露

**原理**：WebRTC 的 ICE 候选过程会泄露真实内网 IP 甚至真实公网 IP，即使用户开启 VPN 也可能暴露。

#### 0.3.1 前端采集

- [x] **修改** `web/src/utils/fingerprint.js`
  - 新增 `getWebRTCIPs()` 异步函数
  - 创建 `RTCPeerConnection`，配置 STUN 服务器 `stun:stun.l.google.com:19302`
  - 监听 `onicecandidate` 事件，正则提取 IP 地址
  - 过滤 `0.0.0.0` 和 `.local`（mDNS）地址
  - 设置 3 秒超时兜底
  - 将采集到的 IP 分类：
    - 私有 IP（`10.*`, `172.16-31.*`, `192.168.*`）→ `webrtcLocalIPs`
    - 公网 IP → `webrtcPublicIPs`
  - 返回格式：`{ localIPs: string[], publicIPs: string[] }`

```javascript
// fingerprint.js 新增:
async function getWebRTCIPs() {
    return new Promise((resolve) => {
        const ips = { local: new Set(), public: new Set() };
        const rtc = new RTCPeerConnection({
            iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
        });
        rtc.createDataChannel("");
        rtc.onicecandidate = (e) => {
            if (!e.candidate) { /* resolve and close */ return; }
            // 提取 IP，分类为 local 或 public
        };
        rtc.createOffer().then(o => rtc.setLocalDescription(o));
        setTimeout(() => resolve(formatResult(ips)), 3000);
    });
}
```

- [x] **修改** `web/src/hooks/useFingerprint.js`
  - 在指纹采集流程中调用 `getWebRTCIPs()`
  - 将结果合并到上报 payload 的 `webrtcIPs` 字段

#### 0.3.2 后端处理

- [x] **修改** `controller/fingerprint.go`
  - 接收新增的 `webrtcLocalIPs` 和 `webrtcPublicIPs` 字段
  - 校验 IP 格式合法性

- [x] **修改** `model/fingerprint.go`
  - 新增字段：
    - `WebRTCLocalIPs string` — JSON 数组字符串，如 `["192.168.1.105"]`
    - `WebRTCPublicIPs string` — JSON 数组字符串
  - 或新建表 `webrtc_ip_records (id, fingerprint_id, ip, ip_type, created_at)`

- [x] **修改** `model/fingerprint_migration.go`
  - WebRTC IP 字段迁移

- [x] **修改** `service/link_analyzer.go`
  - 新增 WebRTC IP 匹配逻辑：
    - 公网 IP 匹配 + 内网 IP 匹配 → 权重 0.95（几乎确定同一设备）
    - 仅内网 IP 匹配 → 权重 0.80（同一局域网/同一设备）
    - 仅公网 IP 匹配 → 权重 0.60（可能是同一出口但不同设备）
  - WebRTC 公网 IP 与请求 IP 不一致时标记为 VPN/代理用户（额外风险信号）

- [x] **修改** `service/risk_scorer.go`
  - 新增风险信号：WebRTC IP ≠ 请求 IP → VPN/代理检测，加风险分

> 进度备注：WebRTC 前后端采集/上报/清洗/匹配/风险信号均已落地。

---

### Task 0.4：P0 阶段配置与集成

- [x] **修改** `common/fingerprint_config.go`
  - 新增权重配置字段：
    ```go
    WeightJA4           float64 `json:"weight_ja4" default:"0.85"`
    WeightETagID        float64 `json:"weight_etag_id" default:"0.80"`
    WeightPersistentID  float64 `json:"weight_persistent_id" default:"0.95"`
    WeightWebRTCPublic  float64 `json:"weight_webrtc_public" default:"0.90"`
    WeightWebRTCLocal   float64 `json:"weight_webrtc_local" default:"0.80"`
    ```
  - 新增开关：`EnableJA4`, `EnableETag`, `EnableWebRTC`（支持独立启停）

- [x] **修改** `web/src/components/auth/RegisterForm.jsx`
  - 注册流程中采集新维度（WebRTC IP、PersistentID）
  - 上报 payload 增加相应字段

- [x] **修改** `web/src/App.jsx`
  - 登录态变化后触发 ETag 追踪请求
  - 触发 PersistentTracker 自愈

- [x] **编写 P0 测试**
  - [x] **修改** `service/link_analyzer_test.go` — 新增 JA4/ETag/WebRTC 匹配的单元测试
  - [x] **修改** `tests/fingerprint/fingerprint_generator.py` — 模拟生成 JA4、ETag、WebRTC 指纹数据
  - [x] **修改** `tests/fingerprint/test_runner.py` — 新增测试场景：VPN用户、清缓存用户、隐身模式用户

> 进度备注：P0 后端配置项、核心单测与前端接线已补齐；Python 场景测试已跑通（A~H 全部 PASS），P0 仅余反代层 JA4 配置片段（方案 A/B）可选补充。

---

## Phase 1 — P1：设备指纹维度翻倍

### Task 1.1：WebGL 深度指纹（升级现有）

**原理**：现有 WebGL 指纹过于简单，应提取 40+ 参数（MAX_TEXTURE_SIZE、精度信息、扩展列表等），以及完整的着色器精度格式。

- [x] **修改** `web/src/utils/fingerprint.js`
  - 重构现有 WebGL 采集函数为 `getDeepWebGLFingerprint()`
  - 新增采集项：
    - 17+ 个 `gl.getParameter()` 值（MAX_TEXTURE_SIZE, MAX_VIEWPORT_DIMS, MAX_VERTEX_ATTRIBS, MAX_VARYING_VECTORS 等）
    - `WEBGL_debug_renderer_info` 扩展获取 `UNMASKED_VENDOR_WEBGL` 和 `UNMASKED_RENDERER_WEBGL`
    - `gl.getSupportedExtensions()` 完整列表（排序后哈希）
    - 12 个着色器精度格式：VERTEX/FRAGMENT × LOW/MEDIUM/HIGH × FLOAT/INT 的 `rangeMin, rangeMax, precision`
  - 优先尝试 `webgl2`，降级到 `webgl`
  - 输出：`{ hash, renderer, vendor, extensionCount, maxTextureSize }`

- [x] **修改** `model/fingerprint.go`
  - 现有 WebGL 字段保留兼容，新增 `WebGLDeepHash string` 字段
  - 新增 `WebGLRenderer string` 和 `WebGLVendor string`（明文存储，方便后台查看）

- [x] **修改** `service/link_analyzer.go`
  - WebGL 深度指纹匹配权重从原来的值提升到 0.88
  - `WebGLDeepHash` 精确匹配作为主要判断
  - `WebGLRenderer` + `WebGLVendor` 完全相同作为辅助信号

> 进度备注：P1.1 已完成，WebGL 深度指纹采集、存储与匹配权重接入均已落地。

---

### Task 1.2：ClientRects 指纹

**原理**：不同操作系统/浏览器/字体渲染引擎对同一文本的 `getBoundingClientRect()` 返回微妙不同的宽高值，比 Canvas 更难被反指纹扩展拦截。

- [x] **修改** `web/src/utils/fingerprint.js`
  - 新增 `getClientRectsFingerprint()` 函数
  - 创建不可见 `<span>` 元素，依次测试：
    - 4 个字体族：`monospace`, `sans-serif`, `serif`, `cursive`
    - 4 个测试字符串：`"mmmmmmmmmmlli"`, `"The quick brown fox jumps"`, `"WMwi1lI0O"`, `"あいうえお"`
    - 固定样式：`font-size: 16px; position: absolute; left: -9999px; line-height: normal`
  - 记录每个组合的 `rect.width` 和 `rect.height`（保留完整精度）
  - 对完整结果 JSON 做 SHA-256 哈希
  - 测量完毕后移除所有临时 DOM 元素

- [x] **修改** `model/fingerprint.go` — 新增 `ClientRectsHash string` 字段
- [x] **修改** `model/fingerprint_migration.go` — 迁移
- [x] **修改** `service/link_analyzer.go` — 匹配权重 0.80

> 进度备注：P1.2 已完成，ClientRects 采集与后端匹配链路已接通并通过相关测试。

---

### Task 1.3：HTTP Header 指纹（服务端零成本）

**原理**：不同浏览器/配置/代理发送的 HTTP 请求头的**顺序和内容组合**不同，用户很难修改请求头顺序。

- [x] **修改** `middleware/fingerprint_collect.go`
  - 在现有 IP/UA 采集的同一位置，新增 HTTP Header 指纹提取
  - 提取内容：
    1. **请求头顺序哈希**：`[h.Key for h in request.Headers]` → Join(",") → MD5
    2. **Accept 系列指纹**：`Accept` + `Accept-Encoding` + `Accept-Language` → 拼接 → MD5
    3. **特殊头存在性位图**：`DNT`, `Upgrade-Insecure-Requests`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `Sec-Fetch-Dest` 的存在/缺失 → 二进制字符串如 `"10110"`
    4. **Client Hints**：`Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Mobile` 值拼接
  - 将以上 4 部分合并哈希为 `httpHeaderFingerprint`
  - 与指纹数据一起异步落库

```go
// fingerprint_collect.go 新增:
func extractHeaderFingerprint(c *gin.Context) string {
    // 1. 头部顺序
    var headerNames []string
    for _, param := range c.Request.Header {
        // ...
    }
    // 注意：Go 的 net/http 会对 Header 排序，需要从 raw request 获取原始顺序
    // 方案：在 Nginx 层用 $http_* 拼接传入，或使用 c.Request.Header 的遍历顺序
}
```

- [x] **注意事项**：Go 的 `net/http` 会将 Header 存入 map（无序），若需要精确的头部顺序指纹，需要在反代层（Nginx/OpenResty）记录原始顺序并通过自定义 Header 传入，或者解析原始请求。考虑用 `Accept` 系列 + 特殊头存在性 + Client Hints 的组合哈希作为替代方案（这些是有值的，不依赖顺序）。

- [x] **修改** `model/fingerprint.go` — 新增 `HTTPHeaderHash string` 字段
- [x] **修改** `model/fingerprint_migration.go` — 迁移
- [x] **修改** `service/link_analyzer.go` — 匹配权重 0.60

> 进度备注：P1.3 已完成，HTTP Header 指纹采集、字段落库、候选召回与匹配权重链路已接通并通过相关测试。

---

### Task 1.4：MediaDevices 指纹

**原理**：枚举用户的摄像头/麦克风/扬声器设备数量和 ID 组合，不同电脑的设备组合天然不同。

- [x] **修改** `web/src/utils/fingerprint.js`
  - 新增 `getMediaDevicesFingerprint()` 异步函数
  - 调用 `navigator.mediaDevices.enumerateDevices()`
  - 统计：`audioinput` / `audiooutput` / `videoinput` 各自数量
  - 收集 `deviceId`（排序后哈希）与 `groupId`（去重排序后哈希）
  - 权限受限时降级返回空哈希与 0 计数，不阻塞整体采集
  - 输出：`{ deviceCount, deviceIdHash, groupIdHash, totalDevices }`

- [x] **修改** `model/fingerprint.go`
  - 新增 `MediaDevicesHash string`
  - 新增 `MediaDeviceCount string`
  - 新增 `MediaDeviceGroupHash string`
  - 新增 `MediaDeviceTotal int`
  - `UserDeviceProfile` 同步新增以上字段并支持兜底映射

- [x] **修改** `model/fingerprint_migration.go`
  - 新增 `media_devices_hash` / `media_device_group_hash` 索引
  - `user_device_profiles` 侧同步索引

- [x] **修改** `service/link_analyzer.go`
  - 召回接入 `media_devices_hash` + `media_device_group_hash`
  - 评分接入 `media_devices_hash` + `media_device_group_hash` + `media_device_count`（加权，不作为强信号短路）

> 进度备注：P1.4 已完成，media devices 前后端采集、落库、召回、评分与测试链路已打通。

---

### Task 1.5：SpeechSynthesis 语音引擎指纹

**原理**：每台电脑安装的 TTS 语音引擎列表不同（取决于操作系统版本、语言包、第三方 TTS 软件），很少有人会修改。

- [x] **修改** `web/src/utils/fingerprint.js`
  - 新增 `getSpeechVoicesFingerprint()` 异步函数
  - 调用 `speechSynthesis.getVoices()`，兼容 `voiceschanged` 与超时兜底
  - 对 voice 提取 `name|lang|localService`，排序后哈希
  - 输出：`{ voiceHash, voiceCount, localVoiceCount }`

- [x] **修改** `model/fingerprint.go`
  - 新增 `SpeechVoicesHash string`
  - 新增 `SpeechVoiceCount int`
  - 新增 `SpeechLocalVoiceCount int`
  - `UserDeviceProfile` 同步新增并支持兜底映射

- [x] **修改** `model/fingerprint_migration.go`
  - 新增 `speech_voices_hash` 索引（`user_fingerprints` 与 `user_device_profiles`）

- [x] **修改** `service/link_analyzer.go`
  - 召回接入 `speech_voices_hash`
  - 评分接入 `speech_voices_hash` + `speech_voice_count` + `speech_local_voice_count`（加权，不作为强信号短路）

> 进度备注：P1.5 已完成，speech voices 采集、落库、召回、评分与测试链路已打通。

---

### Task 1.6：P1 阶段集成

- [x] **修改** `web/src/hooks/useFingerprint.js`
  - 上报链路继续使用 `Promise.allSettled()` 采集产物，单点失败不阻塞整体
  - HTTP Header 指纹仍由服务端采集，不依赖前端输入

- [x] **修改** `controller/fingerprint.go`
  - 接收并写入新字段（含 media/speech）
  - `HTTPHeaderHash` 仅信任服务端 context（`http_header_fingerprint`），不信任 body fallback

- [x] **修改** `controller/user.go`
  - 注册路径接入新维度写入与设备档案 upsert

- [x] **修改** `model/fingerprint_migration.go`
  - 合并 P1 新增字段索引
  - 补充 `user_device_profiles.http_header_hash` 索引

- [x] **修改** `common/fingerprint_config.go`
  - 新增/补全权重 getter：
    - `GetFingerprintWeightMediaDevicesHash`
    - `GetFingerprintWeightMediaDeviceGroupHash`
    - `GetFingerprintWeightMediaDeviceCount`
    - `GetFingerprintWeightSpeechVoicesHash`
    - `GetFingerprintWeightSpeechVoiceCount`
    - `GetFingerprintWeightSpeechLocalVoiceCount`

- [x] **修改** `service/association_query.go` / `service/cron_fingerprint.go`
  - 管理端关联查询与全量扫描纳入 P1 新维度

- [x] **修改** `web/src/pages/Admin/Fingerprint.jsx`
  - 继续复用 `UserAssociations` 通用详情表；后端 `details` 已可展示新维度

- [x] **更新测试**
  - [x] `service/link_analyzer_test.go` — 新增 media/speech 维度与 weighted-not-short-circuit 测试
  - [x] `service/association_query_test.go` — 新增 `media_device_group_hash` 候选召回测试
  - [x] `model/fingerprint_test.go` — 新增 `UpsertDeviceProfile` 字段回填测试
  - [x] `controller/fingerprint_report_test.go` / `controller/fingerprint_helpers_test.go` — 新增 `HTTPHeaderHash` 档案映射断言
  - [x] `common/fingerprint_config_test.go` — 新增 media/speech group/count getter 与 fallback 测试

> 进度备注：P1.6 已完成，P1 主链路已形成“采集 → 上报/落库 → 召回 → 评分 → 查询/扫描 → 测试验证”闭环。

---

## Phase 2 — P2：网络 + 时序关联

> 进度快照（以当前 worktree 代码为准）：P2 已大部分落地。2.1 ASN/ISP 分析与 2.3 时序分析主链路已接入；2.3 还已补齐会话级时序预计算、稳定 synthetic `session_id`、按 `source` 替换会话与并发互斥；2.2 DNS 最小链路（前端 probe/session 上报、后端落库/评分接线）已接入，且后端已补齐可选 Cloudflare Analytics 查询兜底代码，但权威 DNS 基础设施与真实部署配置仍延后；管理端 `/api/admin/fingerprint/user/:id/temporal` 与 `/api/admin/fingerprint/user/:id/network` 及前端展示链路已打通。

### P2 parse 2 已完成摘要（以当前 worktree 代码为准）

- [x] ASN 相似度评分已接入 `service/link_analyzer.go`
- [x] 时序画像读取/实时回退已接入 `service/temporal_analyzer.go`
- [x] `time_similarity` / `mutual_exclusion` 已接入评分逻辑，且仅在存在有效证据时参与评分
- [x] 时序画像预计算已接入 `service/cron_fingerprint.go`（`FullLinkScan()` 前刷新 `RefreshTemporalProfilesCron(120)`）
- [x] 会话级时序预计算已接入 `service/temporal_analyzer.go`（稳定 synthetic `session_id` + `precompute` 来源会话写入）
- [x] 时序预计算并发互斥已接入 `service/temporal_analyzer.go`（防止小时任务与全量扫描重叠重复刷新）
- [x] 管理端最小可用：`/api/admin/fingerprint/user/:id/temporal` 已可用
- [x] `/api/admin/fingerprint/user/:id/network` 与前端 network 展示链路已确认打通
- [x] 关键后端定向测试已覆盖时序预计算、稳定会话 ID、按 `source` 替换与评分接线（`service/cron_fingerprint_test.go`、`service/temporal_analyzer_test.go`、`service/link_analyzer_test.go`、`model/temporal_model_test.go`）
- [ ] DNS 泄露检测的真实基础设施与部署配置仍未完成（但最小前后端链路已接入，且后端已补齐可选 Cloudflare Analytics 查询代码）

### Task 2.1：ASN/ISP 网络指纹

**原理**：IP 会变，但用户的运营商（ASN）通常是稳定的。数据中心 IP 可用于检测代理/VPN。

- [x] **复用现有** `service/ip_service.go` 提供 ASN/机房标签（最小可用）
  - 说明：当前未引入 `service/network_fingerprint.go + MaxMind`，先基于既有链路完成 P2 最小闭环

- [x] **修改** `middleware/fingerprint_collect.go`
  - 在 IP 采集后调用 `LookupIP()` 并写入 ASN 信息
  - 将 ASN 信息随指纹数据存储

- [x] **修改** `model/fingerprint.go` 或 `model/ip_ua_history.go`
  - 已接入 `ASN`, `ASNOrg`, `IsDatacenter` 字段与持久化

- [x] **修改** `service/link_analyzer.go`
  - ASN 匹配权重 0.45 已接线（配置化）
  - 已增加噪声过滤：`datacenter` / `vpn` / `proxy` / `tor` 不参与 ASN 重叠计算

- [x] **修改** `service/risk_scorer.go`
  - 数据中心 IP 风险信号已纳入
  - 结合现有 `ip_type` 与 `webrtc public mismatch` 持续计入风险评分

---

### Task 2.2：DNS 泄露检测

**原理**：即使使用代理，DNS 请求可能走真实网络路径，通过观察 DNS 解析器 IP 可发现用户真实网络环境。

- [x] **评估可行性**（当前 worktree 采用方案 C 的最小实现，真实日志基础设施后置）
  - 方案 A：自建权威 DNS 服务器（使用 `miekg/dns` Go 库），记录查询来源 IP
  - 方案 B：使用 Cloudflare 的 DNS Analytics API
  - 方案 C（轻量替代，当前 worktree 已接入最小埋点）：客户端用 `fetch()` 请求唯一子域名，为后续服务端日志解析预留 `probe_id` 链路

- [x] **若实施方案 C（当前 worktree 的最小实现）**：
  - [x] **修改** `web/src/utils/fingerprint.js`
    - 已新增可选 `triggerDNSProbe()`（受 `VITE_FINGERPRINT_DNS_PROBE_DOMAIN_SUFFIX` 控制）
    - 已补齐 `dns_probe_id`、`session_id`、`session_start_at`、`session_end_at`
    - 实际登录上报触发位于 `web/src/hooks/useFingerprint.js`
  
  - [x] **新建** `service/dns_leak.go`（当前为最小后端兜底 + 可选 Cloudflare 查询）
    - 已实现 `dns_resolver_ip` 的 sanitize / normalize
    - 已补齐受配置控制的 Cloudflare Analytics 查询兜底代码；未配置 zone/token 或无真实 DNS 日志基础设施时回退到 fallback sanitize
    - `probe_id` 链路已保留并用于 Cloudflare 查询参数/后续权威 DNS 扩展

  - [x] **修改** `model/fingerprint.go`
    - 已新增 `DNSResolverIP string` 字段并用于候选召回

  - [x] **修改** `service/link_analyzer.go` — DNS 解析器 IP 匹配权重 0.50
    - 已接入 DNS 维度权重、特征开关与候选召回

> **实施建议**：DNS 泄露检测的基础设施要求较高（需要自有域名的权威 DNS 可编程），如果当前基础设施不支持，可以先保留当前最小链路，后续再补权威 DNS / Cloudflare 日志对接。

> 进度备注：当前 worktree 已补齐前端 `probe/session` 上报、后端 `dns_resolver_ip` 落库与评分接线，并补齐可选 Cloudflare Analytics 查询代码；但真实 DNS 日志基础设施与线上部署配置仍未落地，因此整体仍属于“部分完成”。

---

### Task 2.3：登录时间模式分析

**原理**：同一人操作两个账号的活跃时间段往往高度重叠，且存在互斥模式（A 在线时 B 不在，反之亦然）。

- [x] **新建** `service/temporal_analyzer.go`
  - 已实现 `BuildActivityProfile(loginTimestamps []time.Time) []float64`
  - 已实现 `CompareProfiles(profileA, profileB []float64)`（余弦相似度）
  - 已实现 `CheckMutualExclusion(timestampsA, timestampsB []time.Time, windowMinutes int)`
  - 已实现 `SessionGapAnalysis(sessionsA, sessionsB []SessionWindow) GapResult`（最小版本）
  - 已加入质量收敛：最小样本门槛（5）+ 90 秒 burst 去重 + 互斥计数防目标事件复用

- [x] **修改** `model/temporal_profile.go` / `controller/fingerprint.go`
  - 当前 worktree 已落地 `UserSession` 持久化与 `fingerprint` 来源会话写入
  - `RefreshTemporalProfileForUser()` 已改为按 `source` 替换会话，避免预计算覆盖真实 fingerprint sessions

- [x] **修改** `service/link_analyzer.go`
  - 已集成 `time_similarity`（余弦相似度）与 `mutual_exclusion` 维度（配置化权重）
  - `time_similarity` / `mutual_exclusion` 仅在样本证据满足时参与评分，降低误报

- [x] **修改** `service/cron_fingerprint.go`
  - 已在 `FullLinkScan()` 前刷新时序画像缓存（`RefreshTemporalProfilesCron(120)`）
  - 当前 worktree 已落地会话级时序预计算：按时间窗口生成稳定 synthetic `session_id`，并以 `precompute` 来源写入 `user_sessions`，不会覆盖真实 `fingerprint` 会话

---

### Task 2.4：P2 阶段配置与集成

- [x] **修改** `common/fingerprint_config.go`
  - P2 权重和开关已接入（含 `WeightASN/WeightTimeSimilarity/WeightMutualExclusion`、`EnableASNAnalysis/EnableTemporalAnalysis`）

- [x] **修改** `controller/admin_fingerprint.go`
  - 管理端接口已确认可用：
    - `GET /api/admin/fingerprint/user/:id/temporal`
    - `GET /api/admin/fingerprint/user/:id/network`

- [x] **修改** `web/src/pages/Admin/UserAssociations.jsx`
  - temporal 画像展示链路已接通并展示（profile bins / 样本数 / 高峰时段）
  - network 展示链路已接通并展示（history_count / datacenter_rate / asn_stats）

- [x] **更新测试**
  - [x] `service/link_analyzer_test.go` — 增加 ASN/time/mutual/DNS 维度与证据门槛测试
  - [x] `service/temporal_analyzer_test.go` — 增加互斥计数、防复用、最小样本、burst 去重、稳定 precompute `session_id` 与会话级预计算测试
  - [x] `controller/fingerprint_report_test.go` — 增加 DNS/session 持久化断言
  - [x] `model/temporal_model_test.go` — 增加 `UpsertUserSession` 并发唯一性、空 `session_id` 归一化与按 `source` 替换会话测试

---

## Phase 3 — P3：生物特征级识别

### Task 3.1：打字节奏指纹（Keystroke Dynamics）

**原理**：每个人的打字节奏（按键持续时间、键间间隔、常用双键组合速度）是肌肉记忆级别的唯一标识，极难伪造。

- [x] **新建** `web/src/utils/keystroke.js`
  - 实现 `KeystrokeDynamics` 类：
    - `startCapture(inputElement)` — 监听 keydown/keyup 事件
    - 记录每个按键的时间戳和类型（down/up）
    - 计算 digraph（双键组合）间隔统计
    - `getFingerprint()` 返回：
      - `avgHoldTime` / `stdHoldTime` — 按键持续时间均值和标准差
      - `avgFlightTime` / `stdFlightTime` — 键间间隔均值和标准差
      - `commonDigraphs` — Top 10 常用双键组合的平均间隔和标准差
      - `typingSpeed` — 每秒按键数
    - `reset()` — 清空累积数据
  - 注意隐私：**不记录按键内容**，只记录时间模式

- [x] **修改** `web/src/components/auth/RegisterForm.jsx`
  - 在用户名/密码输入框上绑定 `KeystrokeDynamics` 采集
  - 注册提交时将 keystroke fingerprint 附在 payload 中

- [x] **修改** `web/src/hooks/useFingerprint.js`
  - 登录场景也采集打字节奏（需要在登录页的输入框上绑定）
  - 持续登录后在搜索框/聊天框等输入场景累积采集
  - 当累积样本充足（>100 次按键）时上报一次 profile 更新

- [x] **新建** `service/behavior_analyzer.go`
  - 实现 `CompareKeystrokeProfiles(a, b KeystrokeProfile) float64`
  - 比较算法：
    - `avgHoldTime` 差异 ÷ 平均标准差 → 归一化相似度
    - `avgFlightTime` 差异 ÷ 平均标准差 → 归一化相似度
    - 共同 digraph 的时间间隔相关系数
    - 综合加权得出行为相似度分数（0-1）

- [x] **新建** `model/behavior_profile.go`
  - `KeystrokeProfile` 模型：
    ```go
    type KeystrokeProfile struct {
        UserID          int       `gorm:"index"`
        AvgHoldTime     float64
        StdHoldTime     float64
        AvgFlightTime   float64
        StdFlightTime   float64
        TypingSpeed     float64
        DigraphData     string    // JSON: top digraph stats
        SampleCount     int       // 累积按键样本数
        UpdatedAt       time.Time
    }
    ```

- [x] **修改** `model/fingerprint_migration.go` — 新增行为 profile 表迁移
- [x] **修改** `controller/fingerprint.go` — 接收 keystroke 数据
- [x] **修改** `service/link_analyzer.go` — 打字节奏相似度权重 0.70（样本充足时）

> 进度备注：Task 3.1 已完成，注册/登录/会话内持续采集、后端落库、行为对比与 `link_analyzer` 权重接线均已落地，并补齐对应单测/接口测试。

---

### Task 3.2：鼠标运动轨迹指纹

**原理**：鼠标的移动速度分布、加速度曲线、方向变化频率、滚轮习惯是人的肌肉记忆，每个人都不同。

- [x] **新建** `web/src/utils/mouse_tracker.js`
  - 实现 `MouseBehaviorTracker` 类：
    - `start()` — 监听 mousemove / click / wheel 事件
    - 采样策略：mousemove 事件限频至每 50ms 一个点（避免数据量过大）
    - `getFingerprint()` 返回（需要 ≥50 个移动采样点）：
      - **速度统计**：`avgSpeed`, `maxSpeed`, `speedStd`
      - **加速度特征**：`avgAcceleration`, `accStd`
      - **方向变化频率**：`directionChanges / totalAngles`（反映精确度/手抖）
      - **滚轮习惯**：`avgScrollDelta`, `scrollDeltaMode`
      - **点击分布**：四象限点击比例分布
    - `stop()` — 移除事件监听
    - `reset()` — 清空数据
  - 注意：**不记录点击坐标的绝对位置**（隐私），只记录统计特征

- [x] **修改** `web/src/hooks/useFingerprint.js`
  - 登录后启动 `MouseBehaviorTracker`
  - 采集一段时间（如 60 秒活跃交互后）上报 profile
  - 后续每次访问持续更新 profile（指数移动平均合并新旧数据）

- [x] **修改** `service/behavior_analyzer.go`
  - 新增 `CompareMouseProfiles(a, b MouseProfile) float64`
  - 比较各统计特征的归一化差异
  - 综合得出行为相似度

- [x] **修改** `model/behavior_profile.go`
  - 新增 `MouseProfile` 模型：
    ```go
    type MouseProfile struct {
        UserID              int       `gorm:"index"`
        AvgSpeed            float64
        MaxSpeed            float64
        SpeedStd            float64
        AvgAcceleration     float64
        AccStd              float64
        DirectionChangeRate float64
        AvgScrollDelta      float64
        ClickDistribution   string    // JSON: 四象限比例
        SampleCount         int
        UpdatedAt           time.Time
    }
    ```

- [x] **修改** `service/link_analyzer.go` — 鼠标行为相似度权重 0.65（样本充足时）

> 进度备注：Task 3.2 已完成，前端采集、后端落库、行为对比、持续上报与 `link_analyzer` 权重接线均已落地，并补齐对应单测。

---

### Task 3.3：P3 阶段集成

- [x] **修改** `common/fingerprint_config.go`
  - 新增：
    ```go
    WeightKeystroke         float64 `default:"0.70"`
    WeightMouseBehavior     float64 `default:"0.65"`
    MinKeystrokeSamples     int     `default:"100"` // 最少按键样本数
    MinMouseSamples         int     `default:"50"`  // 最少鼠标采样点
    BehaviorCollectDuration int     `default:"60"`  // 秒
    EnableBehaviorAnalysis  bool    `default:"true"`
    ```

- [x] **修改** `controller/fingerprint.go`
  - 新增接口 `POST /api/fingerprint/behavior` — 接收行为 profile 上报
  - 与设备指纹分开上报（行为 profile 是持续更新的，设备指纹相对稳定）

- [x] **修改** `router/api-router.go` — 注册行为 profile 路由

- [x] **新增测试**
  - [x] `service/behavior_analyzer_test.go` — 行为相似度算法测试
  - [x] `tests/fingerprint/fingerprint_generator.py` — 模拟行为 profile 数据
  - [x] `model/behavior_profile_test.go` / `controller/fingerprint_report_test.go` — 原子落库、接口校验与回滚测试

> 进度备注：Task 3.3 已完成，`/api/fingerprint/behavior` 路由、原子落库与 Python 场景脚本均已补齐。

---

## Phase Final — 综合评分算法重构 + 管理后台

### Task F.1：分层评分算法

**原理**：不再使用简单加权平均，改为分层判定逻辑，模拟人类审核的思考过程。

- [x] **重构** `service/link_analyzer.go` 的核心评分函数
  - 实现分层判定逻辑：

```
第一层：一票通过（强标识命中）
├─ PersistentID 匹配       → 0.99
├─ ETag ID 匹配            → 0.95
├─ WebRTC 公网+内网 IP 匹配 → 0.95
└─ 命中任一 → 直接返回，不继续

第二层：设备指纹加权（计算匹配的设备维度总权重）
├─ Canvas (0.90) + WebGL深度 (0.88) + Audio (0.80)
├─ ClientRects (0.80) + MediaDevices (0.75) + 字体 (0.70)
├─ SpeechVoices (0.65) + JA4 (0.85)
├─ 匹配权重之和 ≥ 3.0 → base_score = 0.85
├─ 匹配权重之和 ≥ 1.5 → base_score = 0.60
└─ 匹配权重之和 < 1.5 → 进入第四层

第三层：网络层佐证
├─ IP 精确匹配 (0.50) + IP子网 (0.40) + ASN (0.45)
├─ WebRTC (0.85) + DNS泄露 (0.50) + HTTP Header (0.60)
└─ 归一化为 network_score (0-1)

第四层：行为层佐证
├─ 打字节奏 (0.70) + 鼠标行为 (0.65)
├─ 时间模式 (0.50) + 互斥分析 (0.55)
└─ 归一化为 behavior_score (0-1)

综合判定：
├─ 设备强匹配(≥3.0) + 任一佐证 → 0.85 + boost(max 0.14)
├─ 设备部分匹配(≥1.5) + 网络强匹配(>0.6) → 0.70 + behavior*0.15
├─ 纯行为分析（隐身模式场景）behavior>0.8 + network>0.5 → 0.60
└─ 兜底: device*0.3 + network*0.3 + behavior*0.2
```

- [x] **修改** `service/link_analyzer.go`
  - 重构 `CalculateSimilarity(accountA, accountB)` 函数
  - 实现上述四层判定
  - 返回 `SimilarityResult { Score float64, Tier string, MatchedDimensions []string, Explanation string }`
  - 保留向后兼容：旧的简单评分逻辑作为 fallback

---

### Task F.2：权重配置管理

- [x] **修改** `common/fingerprint_config.go`
  - 统一管理完整权重表（参照方案中的权重表）
  - 支持从数据库/配置文件动态读取权重（方便调优）
  - 导出 `GetWeights()` 函数供所有 service 层使用

- [x] **修改** `controller/admin_fingerprint.go`
  - 新增管理端权重配置接口：
    - `GET /api/admin/fingerprint/weights` — 查看当前权重
    - `PUT /api/admin/fingerprint/weights` — 更新权重（热更新，无需重启）

---

### Task F.3：管理后台增强

- [x] **修改** `web/src/pages/Admin/Fingerprint.jsx`
  - 指纹详情页展示所有新维度：
    - JA4 指纹值
    - WebRTC 泄露的 IP（标注是否与请求 IP 一致）
    - HTTP Header 指纹
    - WebGL 渲染器/供应商名称
    - 设备数量、语音引擎数量
    - 行为 profile 摘要（打字速度、鼠标速度）
  - 新增「指纹维度命中详情」展示：哪些维度匹配、哪些不匹配

- [x] **修改** `web/src/pages/Admin/UserAssociations.jsx`
  - 关联分析结果页增强：
    - 显示关联判定层级（Tier 1/2/3/4）
    - 显示具体匹配的维度列表和各自权重
    - 时间模式热力图对比（两个用户的 24h 活跃分布并排展示）
    - 互斥切换时间线可视化
    - VPN/代理检测标记

- [x] **修改** `web/src/components/table/users/modals/EditUserModal.jsx`
  - 用户编辑弹窗中的关联查询增加新维度信息

---

### Task F.4：定时任务更新

- [x] **修改** `service/cron_fingerprint.go`
  - 全量扫描任务中新增：
    - 重新计算所有用户对的关联分数（使用新的分层算法）
    - 构建/更新时间活跃 Profile
    - 清理过期的行为 profile 数据（保留期可配置）
    - ASN 数据库定期更新检查
  - 新增增量扫描：当某用户上报了新的指纹维度时，仅重新计算该用户涉及的关联对

---

### Task F.5：最终测试与回归

- [x] **更新** `service/link_analyzer_test.go`
  - [x] 行为画像/设备画像回退链路测试
  - [x] account link 收尾回归：`auto_confirm` CAS、`ReviewLink` action/status 约束
  - [x] 分层判定逻辑测试
  - [x] 边界情况：部分维度缺失时的降级评分测试

- [x] **新增/更新** `model/account_link_test.go`
  - [x] `UpsertLink` 并发唯一性测试
  - [x] 弱证据不覆盖强证据测试
  - [x] 旧数据 `uk_link_pair` 归一与去重测试

- [x] **更新** `tests/fingerprint/` 目录
  - [x] `fingerprint_generator.py` — 模拟全部新维度数据
  - [x] `test_runner.py` — 新增完整测试场景：
    - 场景 1：同一设备 + 同一浏览器 + 不同账号 → 预期高分
    - 场景 2：同一设备 + 隐身模式 → 预期中高分（靠 JA4 + 行为）
    - 场景 3：同一设备 + VPN → 预期中高分（靠 WebRTC + 设备指纹）
    - 场景 4：同一设备 + 清缓存 → 预期中高分（靠 ETag + 设备指纹）
    - 场景 5：不同设备 + 同一人 → 预期中分（靠行为 + 时序）
    - 场景 6：完全不同用户 → 预期低分

> 进度备注：当前 worktree 已完成 Final 阶段分层评分回归与 Python 六场景脚本补齐；并通过定向验证：`go test ./service -run 'TestCalculateSimilarity_(TierBuckets|DegradesWhenEvidenceGoesMissing)$' -count=1`、`python -m py_compile tests/fingerprint/fingerprint_generator.py tests/fingerprint/test_runner.py tests/fingerprint/reporter.py tests/fingerprint/config.py`。

---

## 附录

### A. 新增文件清单

| 路径 | 说明 | 阶段 |
|------|------|------|
| `deploy/nginx/ngx_ja4.conf` | Nginx/OpenResty JA4 采集配置 | P0 |
| `controller/etag_tracker.go` | ETag 追踪端点 | P0 |
| `service/dns_leak.go` | DNS 泄露检测服务 | P2 |
| `service/temporal_analyzer.go` | 登录时间模式分析服务 | P2 |
| `service/temporal_analyzer_test.go` | 时间分析单元测试 | P2 |
| `service/behavior_analyzer.go` | 行为（打字+鼠标）对比服务 | P3 |
| `service/behavior_analyzer_test.go` | 行为分析单元测试 | P3 |
| `model/behavior_profile.go` | 行为 profile 模型 | P3 |
| `web/src/utils/keystroke.js` | 打字节奏采集 | P3 |
| `web/src/utils/mouse_tracker.js` | 鼠标行为采集 | P3 |

### B. 主要修改文件清单

| 路径 | 修改内容 | 阶段 |
|------|----------|------|
| `web/src/utils/fingerprint.js` | 新增 PersistentTracker / WebRTC / ClientRects / MediaDevices / SpeechVoices / WebGL 深度 / ETag 触发 | P0+P1 |
| `web/src/hooks/useFingerprint.js` | 集成所有新采集维度 + 行为采集 | P0-P3 |
| `web/src/components/auth/RegisterForm.jsx` | 注册时采集新维度并附带 keystroke 行为画像 | P0+P3 |
| `web/src/components/auth/LoginForm.jsx` | 登录页打字节奏采集与行为画像接线 | P3 |
| `web/src/App.jsx` | 登录后触发 ETag + PersistentTracker | P0 |
| `middleware/fingerprint_collect.go` | JA4 读取 + HTTP Header 指纹 + ASN 分析 | P0+P1+P2 |
| `controller/fingerprint.go` | 接收所有新指纹字段 + 行为 profile + `/api/fingerprint/behavior` | P0-P3 |
| `controller/admin_fingerprint.go` | 新管理端分析接口 | P2+Final |
| `model/fingerprint.go` | 新增 12+ 字段 + 原子落库行为画像 | P0-P3 |
| `model/fingerprint_migration.go` | 对应迁移 + account link/behavior profile 索引保障 | P0-P3 |
| `model/account_link.go` | 账号关联 upsert、状态 CAS、唯一索引归一/去重 | Final |
| `model/account_link_test.go` | account link 并发唯一性与回归测试 | Final |
| `model/behavior_profile_test.go` | 行为画像原子落库与唯一约束测试 | P3 |
| `service/link_analyzer.go` | 新维度匹配 + 账号关联收尾修复（非完整 Final 分层重构） | P0-Final |
| `service/link_analyzer_test.go` | 全维度测试 + account link 回归 | P0-Final |
| `service/risk_scorer.go` | VPN/代理/数据中心检测 | P0+P2 |
| `service/cron_fingerprint.go` | 时间 Profile 构建 + 增量扫描 | P2+Final |
| `common/fingerprint_config.go` | 所有新权重和开关 | P0-Final |
| `router/api-router.go` | ETag 路由 + 行为 profile 路由 + 管理路由 | P0+P3+Final |
| `web/src/pages/Admin/Fingerprint.jsx` | 新维度展示 | P1+Final |
| `web/src/pages/Admin/UserAssociations.jsx` | 关联结果页增强与管理动作接线 | Final |
| `web/src/hooks/useFingerprint.helpers.js` | 基础指纹/行为画像拆分上报与重试控制 | P3 |
| `web/src/hooks/useFingerprint.helpers.test.js` | 行为画像上报拆分与重试测试 | P3 |
| `tests/fingerprint/fingerprint_generator.py` | 模拟新维度 | P0-P3 |
| `tests/fingerprint/test_runner.py` | 新测试场景 | P0-Final |

### C. 数据库 Schema 变更汇总

```sql
-- P0 新增字段 (fingerprint 表)
ALTER TABLE device_fingerprints ADD COLUMN ja4 VARCHAR(128) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN etag_id VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN persistent_id VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN persistent_id_source VARCHAR(32) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN webrtc_local_ips TEXT DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN webrtc_public_ips TEXT DEFAULT '';
CREATE INDEX idx_ja4 ON device_fingerprints(ja4);
CREATE INDEX idx_etag_id ON device_fingerprints(etag_id);
CREATE INDEX idx_persistent_id ON device_fingerprints(persistent_id);

-- P1 新增字段
ALTER TABLE device_fingerprints ADD COLUMN webgl_deep_hash VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN webgl_renderer VARCHAR(256) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN webgl_vendor VARCHAR(256) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN client_rects_hash VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN http_header_hash VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN media_devices_hash VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN media_device_count VARCHAR(16) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN speech_voices_hash VARCHAR(64) DEFAULT '';
ALTER TABLE device_fingerprints ADD COLUMN speech_voice_count INT DEFAULT 0;

-- P2 新增字段 (ip_ua_history 或 fingerprint 表)
ALTER TABLE ip_ua_histories ADD COLUMN asn INT DEFAULT 0;
ALTER TABLE ip_ua_histories ADD COLUMN asn_org VARCHAR(128) DEFAULT '';
ALTER TABLE ip_ua_histories ADD COLUMN is_datacenter BOOLEAN DEFAULT FALSE;
ALTER TABLE ip_ua_histories ADD COLUMN dns_resolver_ip VARCHAR(45) DEFAULT '';

-- P2 新增表
CREATE TABLE user_sessions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_start DATETIME NOT NULL,
    session_end DATETIME,
    ip VARCHAR(45),
    fingerprint_hash VARCHAR(64),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_session (user_id, session_start)
);

CREATE TABLE activity_profiles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL UNIQUE,
    hour_distribution TEXT NOT NULL, -- JSON: 48-bin histogram
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_activity (user_id)
);

-- P3 新增表
CREATE TABLE keystroke_profiles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL UNIQUE,
    avg_hold_time FLOAT,
    std_hold_time FLOAT,
    avg_flight_time FLOAT,
    std_flight_time FLOAT,
    typing_speed FLOAT,
    digraph_data TEXT, -- JSON
    sample_count INT DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_keystroke (user_id)
);

CREATE TABLE mouse_profiles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL UNIQUE,
    avg_speed FLOAT,
    max_speed FLOAT,
    speed_std FLOAT,
    avg_acceleration FLOAT,
    acc_std FLOAT,
    direction_change_rate FLOAT,
    avg_scroll_delta FLOAT,
    click_distribution TEXT, -- JSON
    sample_count INT DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_mouse (user_id)
);

-- P0 新增表 (ETag 追踪)
CREATE TABLE etag_tracking (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    etag_id VARCHAR(64) NOT NULL,
    user_id INT DEFAULT 0,
    fingerprint_hash VARCHAR(64) DEFAULT '',
    ip VARCHAR(45),
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    visit_count INT DEFAULT 1,
    INDEX idx_etag (etag_id),
    INDEX idx_etag_user (user_id)
);
```

### D. 依赖项

```
# Go 依赖
go get github.com/oschwald/geoip2-golang  # P2: ASN/GeoIP 查询
# 下载 GeoLite2-ASN.mmdb 和 GeoLite2-City.mmdb 到 data/ 目录

# 前端无新依赖（全部使用浏览器原生 API）

# 基础设施（P0）
# - Nginx/OpenResty 需安装 JA4 模块或使用 lua 脚本
# - 或在 Go 应用层 TLS 配置中 hook ClientHelloInfo（备选方案）
```

### E. 实施注意事项

1. **隐私合规**：所有行为采集（打字、鼠标）仅记录统计特征，不记录具体内容或精确坐标。在隐私政策中声明设备指纹采集用途。
2. **性能影响**：前端采集用 `Promise.allSettled()` 并行执行，设置总超时 5 秒。后端匹配在异步 goroutine 中执行，不阻塞主请求。
3. **降级策略**：每个新维度都有独立开关。任何单一维度采集失败（浏览器不支持、权限不足）不影响整体评分，只是该维度权重不参与计算。
4. **数据迁移**：使用 GORM 的 `AutoMigrate` 实现幂等迁移，新增字段全部有默认值，不影响现有数据。
5. **JA4 部署选择**：如果反代改造成本高，P0 可以先跳过 JA4，优先实施 ETag + WebRTC + 多存储持久化（这三个纯应用层即可完成）。