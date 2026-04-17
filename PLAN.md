# PLAN.md — 关联账号查询 504 治理任务计划

> **目标**：将 `/api/admin/fingerprint/user/:id/associations` 从“点击即现场重算”升级为“快路径优先 + 后台刷新 + 受控重算”，消除 504，并在几千指纹规模下保持稳定延迟。
>
> **范围**：仅涉及关联查询链路（controller/service/model、缓存、可观测性、网关超时协同），不改变现有关联语义与排序规则。
>
> **验收总目标**：
> - 504 比例：**0**
> - 接口 p95：**< 2s**
> - 接口 p99：**< 5s**
> - 缓存命中时延：**100~400ms 级**

---

## 1. 问题定义（基于现状证据）

- 请求已发出且到达网关，但返回 `504 Gateway Timeout`：`1.md:7`
- 网关服务标识为 `openresty`：`1.md:29`
- 当前核心入口：`controller/admin_fingerprint.go:150`
- 当前主计算路径：`service/association_query.go:206`
- 当前重循环热点：`service/association_query.go:346-347`
- 用户级昂贵计算在相似度阶段被重复触发：
  - `service/link_analyzer.go:796-798`（`ComputeIPOverlap`）
  - `service/link_analyzer.go:825-827`（`GetSharedIPs`）
- 当前缓存 TTL：
  - 正缓存 `30m`：`service/association_query.go:71`
  - 负缓存 `5m`：`service/association_query.go:72`

---

## 2. 实施原则

1. **先止血再提速**：先避免 504，再优化冷路径。
2. **读快写慢**：查询优先走缓存/快照，重算放后台。
3. **算法不变，执行方式变**：不改判分语义，只改计算时机与复用方式。
4. **三库兼容**：SQLite/MySQL/PostgreSQL 同步可用。

---

## 3. 分阶段任务

## Phase 0（当天可落地）：先把 504 打掉

### T0-1 网关与应用双超时协同

- [ ] 网关侧将本接口 `proxy_read_timeout` 临时提升到 15s（仅兜底）
- [ ] 应用侧增加更短业务超时（建议 8s），优先返回可控结果而不是被网关硬超时
- [ ] 在超时返回中给出明确错误码/错误信息（区分“计算超时”与“内部错误”）

**涉及位置**：`controller/admin_fingerprint.go:150`

**验收**：
- [ ] 连续压测/真实访问下 504 明显下降（目标 0）
- [ ] 超时场景返回业务可识别错误，不再全靠网关 504

---

### T0-2 快速降载参数（Fast 档）

- [ ] 将目标与候选指纹采样从 10 下调到 3（或 3~5 可配置）
- [ ] 保持默认查询参数为轻量组合：
  - `include_details=false`
  - `include_shared_ips=false`
- [ ] 保留原有“完整查询”能力，作为显式模式触发

**涉及位置**：
- `service/association_query.go:271`
- `service/association_query.go:329`
- `controller/admin_fingerprint.go:157-161`

**验收**：
- [ ] 冷请求耗时立刻可见下降
- [ ] 结果可用性不受明显影响

---

## Phase 1（1~3 天）：消除核心重复计算

### T1-1 将用户级昂贵特征移出指纹对内循环

当前问题：`targetFPs x candidateFPs` 双循环内反复触发用户级逻辑，重复开销大。

- [ ] 为单次请求引入 memo cache（map）
- [ ] 下列计算改为“每个 candidate 用户最多一次”：
  - `ComputeIPOverlap`
  - `GetSharedIPs`
  - 其他用户级聚合维度（若存在）
- [ ] `CalculateSimilarity` 保持打分语义不变，仅改数据来源（读 memo）

**涉及位置**：
- `service/association_query.go:346-347`
- `service/link_analyzer.go:627`
- `service/link_analyzer.go:796-798`
- `service/link_analyzer.go:825-827`

**验收**：
- [ ] 相同候选规模下 CPU/DB 开销显著下降
- [ ] 打分结果排序与置信度无语义回归

---

### T1-2 候选预算进一步收紧（控制 pair 数）

- [ ] 调整候选预算参数：
  - `MaxPerSource`
  - `MaxLowSignalPerSource`
  - `MaxTotal`
- [ ] 为低信号来源（IP/子网）设置更保守配额
- [ ] 增加预算命中日志，便于回归调参

**涉及位置**：
- `service/link_analyzer.go:195`
- `service/link_analyzer.go:250`
- `service/association_query.go:291-301`

**验收**：
- [ ] 候选规模受控，极端用户不再放大为超长尾请求
- [ ] 误杀率在可接受范围（结合人工抽样）

---

## Phase 2（2~5 天）：查询路径“快读 + 后台刷新”

### T2-1 SWR（stale-while-revalidate）返回策略

- [ ] 查询优先返回“最近可用结果”（缓存/快照）
- [ ] 若命中旧结果，则后台异步触发刷新
- [ ] 前台可拿到 `analyzed_at` 判断新鲜度

**涉及位置**：
- `service/association_query.go:237-253`
- `service/association_query.go:440-448`
- `controller/admin_fingerprint.go:213`

**验收**：
- [ ] 大多数请求不再阻塞等待重算
- [ ] 数据新鲜度与响应速度取得可控平衡

---

### T2-2 缓存键增加模式维度

- [ ] 在现有 key 基础上增加 `mode`（如 `fast/full`）
- [ ] 避免不同查询模式互相污染缓存
- [ ] TTL 策略保持：正缓存 30m、负缓存 5m（必要时按模式细分）

**涉及位置**：
- `service/association_query.go:156-179`
- `service/association_query.go:71-72`

**验收**：
- [ ] 缓存命中率提升且语义正确
- [ ] 无“轻量结果覆盖完整结果”问题

---

## Phase 3（3~7 天）：预计算主读路径（根治点击现算）

### T3-1 引入关联结果预计算表（主读）

- [ ] 新增结果表（示意）：`user_association_snapshot`
- [ ] 字段建议：
  - `target_user_id`
  - `candidate_user_id`
  - `confidence`
  - `tier`
  - `matched_dimensions_count`
  - `last_analyzed_at`
  - `version`
- [ ] 建唯一索引：`(target_user_id, candidate_user_id)`
- [ ] 查询接口优先读该表 TopN，重算转后台

**注意**：字段类型坚持三库兼容（优先 TEXT/NUMERIC，避免 JSONB 绑定）。

**涉及位置**：
- model 新增/迁移文件
- `service/link_analyzer.go:135`（接入增量更新）
- `service/association_query.go:206`（切主读路径）

**验收**：
- [ ] 点击查询几乎不触发全量重算
- [ ] 接口时延稳定在缓存/快照级别

---

### T3-2 增量更新触发链路

- [ ] 在指纹落库后触发受控增量分析
- [ ] 限流与去抖（同用户短时间多次更新合并）
- [ ] 失败重试与死信记录

**涉及位置**：
- `service/link_analyzer.go:135-140`
- 指纹写入后的调用链（model/service）

**验收**：
- [ ] 更新可追踪、可重试、可观测
- [ ] 不拖慢主写入路径

---

## Phase 4（并行）：可观测性与容量治理

### T4-1 分段耗时打点

- [ ] 记录阶段耗时：
  - 候选召回
  - 相似度计算
  - 详情补齐
  - 缓存读写
- [ ] 记录关键规模指标：
  - `candidates_found`
  - `pair_count`
  - `final_count`
  - `cache_hit`

**涉及位置**：`service/association_query.go:214`

**验收**：
- [ ] 可直接定位瓶颈段，而非只看总耗时

---

### T4-2 SLO 与告警

- [ ] 建立接口 SLO：p95/p99/错误率
- [ ] 告警阈值：
  - 5xx 比例
  - 超时比例
  - 冷请求异常放大
- [ ] 发布后 24h/72h 回看机制

**验收**：
- [ ] 性能回退能在分钟级发现

---

## 4. 复杂度与预期收益

- **Phase 0**：低复杂度，立即见效（先止血）
- **Phase 1**：中复杂度，高收益（核心提速）
- **Phase 2**：中复杂度，高稳定性收益（用户体感提升）
- **Phase 3**：中高复杂度，根治点击现算（规模化必选）

预估提速（以当前链路为基线）：
- 冷请求：**2x~4x**（优化充分可达 **4x~6x**）
- 热请求（命中缓存/快照）：**10x+**

---

## 5. 风险与回滚

### 主要风险

- 预算收紧导致召回下降
- SWR 带来短时“旧结果”观感
- 预计算链路引入一致性与重试复杂度

### 回滚策略

- [ ] 参数开关化（采样数、预算、SWR 开关）
- [ ] 保留旧实时路径作为兜底
- [ ] 迁移按“可逆”设计，支持快速禁用新主读路径

---

## 6. 交付顺序（建议）

1. **先做 T0-1/T0-2**：当天消除 504
2. **再做 T1-1/T1-2**：把冷路径压到可接受
3. **接 T2-1/T2-2**：把“点击等待重算”改为“快读+后台刷新”
4. **最后 T3-1/T3-2**：完成规模化根治
5. **全程并行 T4-1/T4-2**：保证可观测与可回归

---

## 7. 完成定义（DoD）

- [ ] 线上 504 清零并持续稳定
- [ ] p95 < 2s，p99 < 5s
- [ ] 查询日志可解释（知道慢在召回、打分还是补齐）
- [ ] 几千指纹规模下，点击查询不再触发重型现算
- [ ] 三库兼容验证通过
