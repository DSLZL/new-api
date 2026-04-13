# PLAN.md — 指纹系统性能与数据库占用优化实施计划

> **目标**：在不改变当前指纹系统业务语义的前提下，优先降低服务端 CPU / IO 压力、控制数据库增长速度、稳定管理后台查询体验，并保持 SQLite / MySQL / PostgreSQL 三库兼容。
>
> **范围**：仅优化现有指纹采集、写入、关联分析、后台查询、保留与归档策略；不新增新的检测维度，不重写现有评分体系。
>
> **原则**：先控流量与热点，再做 schema 优化，最后做结构性解耦；每个阶段都必须可独立上线、可观测、可回滚。

---

## 1. 当前现状与主要瓶颈

### 1.1 写入链路存在写放大
当前每次指纹上报会在单事务内同时写入：

- `user_fingerprints`
- `user_device_profiles`
- `user_sessions`
- `keystroke_profiles`
- `mouse_profiles`

对应入口位于：

- `model/fingerprint.go`
- `model/behavior_profile.go`

这意味着一次上报并不是一次写，而是 3~5 次写入/更新，用户活跃度一高就会放大数据库压力。

### 1.2 全量关联扫描存在 O(n²) 扩展风险
当前 `service/cron_fingerprint.go` 中的 `FullLinkScan()` 会收集所有相关用户后两两配对，再逐 pair 重算快照。随着指纹用户数增长，该路径会成为最明显的 CPU 与数据库热点。

### 1.3 候选发现路径查询扇出较大
当前 `service/link_analyzer.go` 的候选发现同时依赖设备、协议、网络多个维度。召回效果是好的，但在热点用户、共享网络、高并发后台查询场景下，容易形成多路查询放大。

### 1.4 后台查询存在读放大
当前 `service/association_query.go` + `controller/admin_fingerprint.go` + `web/src/pages/Admin/UserAssociations.jsx` 会触发：

- 目标用户基准指纹加载
- 候选用户批量比对
- 共享 IP / 既有关联补查
- temporal / network / devices 等附加请求

后台页在高基数场景下会形成一组连续读请求。

### 1.5 数据库存储增长的主要来源
数据库体积的主要增长来源预计为：

1. `user_fingerprints` 原始流水表
2. `account_links.match_details` 文本明细
3. `user_sessions` / `user_temporal_profiles` 聚合数据

其中行为画像表是按用户 upsert，增长相对可控，不是当前首要矛盾。

---

## 2. 优化目标与验收指标

## 2.1 总体目标

- 降低原始指纹写入频率与事务压力
- 将关联分析从“随数据量线性失控”改为“预算内稳定运行”
- 将后台高频查询从“现算为主”调整为“缓存 + 分阶段加载”
- 将数据库增长从“流水持续膨胀”调整为“热数据受控、冷数据可归档”

## 2.2 阶段验收指标

| 指标 | P0 目标 | P1 目标 | P2 目标 |
|------|---------|---------|---------|
| 指纹写入 QPS / 事务次数 | 下降 35%+ | 下降 45%+ | 长期稳定 |
| 全量/增量关联分析耗时 | 下降 40%+ | 下降 55%+ | 波动显著降低 |
| 管理后台关联页 p95 延迟 | 下降 30%+ | 下降 45%+ | 接近稳定缓存命中延迟 |
| 数据库月增长量 | 下降 30%+ | 下降 50%+ | 可按归档策略线性预测 |
| 三库兼容性 | 无回归 | 无回归 | 无回归 |

---

## 3. 分阶段总览

| 阶段 | 目标 | 是否改 schema | 预计周期 |
|------|------|---------------|----------|
| **Baseline** | 建立指标基线与回归验证框架 | 否 | 1~2 天 |
| **P0** | 控写入、控扫描、控后台查询 | 否 | 1~2 周 |
| **P1** | 补索引、瘦明细、热冷分层 | 是 | 2~4 周 |
| **P2** | 结果物化、归档、长期容量治理 | 是 | 4 周+ |

---

## 4. Baseline：先建立观测基线

### 4.1 目标
在优化前先拿到可比较的事实数据，避免后续只凭感觉判断效果。

### 4.2 实施项

- [ ] 记录当前关键链路耗时与频次
  - 指纹上报总量
  - `PersistFingerprintReportAtomic` 平均耗时
  - `FullLinkScan` 总耗时与 pair 数量
  - `IncrementalLinkScan` 单次耗时
  - `QueryUserAssociations` 平均耗时 / p95
- [ ] 统计主要表的行数与增长速度
  - `user_fingerprints`
  - `account_links`
  - `user_device_profiles`
  - `user_sessions`
  - `user_temporal_profiles`
  - `ip_ua_history`
- [ ] 按三库准备回归验证清单
  - SQLite
  - MySQL
  - PostgreSQL

### 4.3 涉及文件

- `service/cron_fingerprint.go`
- `service/association_query.go`
- `model/fingerprint.go`
- `model/account_link.go`
- `model/behavior_profile.go`

### 4.4 交付物

- 一份优化前基线数据
- 一份三库回归检查清单
- 一套阶段性验收口径

---

## 5. P0：先做无 schema 变更优化

## 5.1 P0 目标
先用最小风险手段，把最明显的写放大、扫描爆炸、后台读放大压下来。

### Task P0-1：服务端短窗口去重，降低原始流水写入频率

**是否改 schema**：否

#### 实施内容

- [ ] 在指纹写入入口增加服务端幂等/去重窗口
- [ ] 对“同用户 + 同设备关键摘要 + 同网络关键摘要”的短时间重复上报减少 `user_fingerprints` 插入频率，但保持现有 `user_sessions`、行为画像与 IP/UA 历史链路的业务语义不变
- [ ] 设置“关键字段变化强制落库”条件，例如：
  - IP 变化
  - ASN 变化
  - UA 主版本变化
  - PersistentID / ETag / WebRTC 公网 IP 变化
- [ ] 保持当前行为画像与设备档案更新逻辑，但减少原始流水表膨胀

#### 涉及文件

- `controller/fingerprint.go`
- `middleware/fingerprint_collect.go`
- `model/fingerprint.go`
- `model/ip_ua_history.go`
- `common/fingerprint_config.go`

#### 预期收益

- 直接减少 `user_fingerprints` 增长速度
- 降低事务频次和写放大
- 为后续分析与查询减小数据基数

#### 风险

- 可能损失少量高频、低变化场景下的时序细节

#### 验收标准

- [ ] 单用户重复刷新/短时操作不再持续插入高重复指纹
- [ ] 关键字段变化时仍然能正常落库
- [ ] 相关测试与现有采集链路无回归

---

### Task P0-2：全量扫描预算化，避免 O(n²) 直接失控

**是否改 schema**：否

#### 实施内容

- [ ] 将 `FullLinkScan()` 改为“分片 + 批次 + 上限”模式
- [ ] 限制单轮最大用户数、最大 pair 数、最大执行时长
- [ ] 全量扫描优先覆盖最近活跃用户，而不是无差别全用户两两重算
- [ ] 保留低频深扫，但切到离峰时段执行

#### 涉及文件

- `service/cron_fingerprint.go`
- `service/link_analyzer.go`
- `common/fingerprint_config.go`

#### 预期收益

- 将最重的 CPU 热点从“数据量越大越不可控”变为“固定预算内可控”
- 减少数据库高峰期扫描压力

#### 风险

- 弱关联的发现时效可能下降

#### 验收标准

- [ ] `FullLinkScan` 单轮执行时间可被配置限制
- [ ] 活跃用户场景下的关联发现结果无明显回退
- [ ] 离峰补扫可以兜底覆盖低频长尾用户

---

### Task P0-3：候选发现加预算，降低热点用户查询扇出

**是否改 schema**：否

#### 实施内容

- [ ] 对 `findCandidates()` 各维度召回设置上限
- [ ] 高权重维度优先召回，低区分度维度延后或限量补充
- [ ] 对共享网络、共享子网等低区分度来源增加截断策略
- [ ] 增量扫描与后台现算共享同一套预算逻辑

#### 涉及文件

- `service/link_analyzer.go`
- `service/association_query.go`
- `common/fingerprint_config.go`

#### 预期收益

- 防止热点用户触发大规模候选集合
- 降低相似度计算与补充查询总量

#### 风险

- 少数长尾候选召回率下降

#### 验收标准

- [ ] 热点用户查询耗时显著下降
- [ ] 关键高置信关联不因截断而明显丢失

---

### Task P0-4：后台关联页拆成主结果 + 懒加载细节

**是否改 schema**：否

#### 实施内容

- [ ] 优先收敛后端列表接口返回体，先裁掉高成本字段，避免前端即使已部分懒加载仍收到过重响应
- [ ] 关联列表接口优先返回轻量字段：用户、置信度、tier、命中维度、既有关联状态
- [ ] 详情字段改为按需加载：
  - `details`
  - `shared_ips`
  - temporal profile
  - network profile
  - devices
- [ ] 前端按展开/选中行为触发附加请求，避免初次打开页面并发爆发

#### 涉及文件

- `controller/admin_fingerprint.go`
- `service/association_query.go`
- `web/src/pages/Admin/UserAssociations.jsx`
- `web/src/pages/Admin/Fingerprint.jsx`

#### 预期收益

- 后台首页响应更稳定
- 单次页面打开时的查询数量显著下降

#### 风险

- 首次展开详情会额外多一次请求

#### 验收标准

- [ ] 后台关联页初次加载时请求数下降
- [ ] 详情展开体验可接受
- [ ] 关联页 p95 明显改善

---

### Task P0-5：缓存键细化，避免粗粒度缓存带来的读浪费

**是否改 schema**：否

#### 实施内容

- [ ] 调整 `QueryUserAssociations()` 缓存键，至少纳入：
  - 用户 ID
  - `min_confidence`
  - `limit`
  - `device_profile_id` / `baseFingerprint` 标识
- [ ] 对“无结果”场景增加短 TTL 负缓存
- [ ] 对后台 `refresh=true` 路径保留强制刷新能力

#### 涉及文件

- `service/association_query.go`
- `common` 中 Redis 相关调用处

#### 预期收益

- 提高缓存复用质量
- 避免缓存一个大对象再在内存中过滤

#### 风险

- key 数量增加

#### 验收标准

- [ ] 缓存命中逻辑与查询参数严格一致
- [ ] 热用户后台查询重复打开时明显更快

---

### Task P0-6：过期清理改为小批次循环，避免长事务删除

**是否改 schema**：否

#### 实施内容

- [ ] 将 `CleanOldFingerprints()` 从单次大删除改为小批次循环删除
- [ ] 将行为画像清理改为同样的小批次策略
- [ ] 为 `ip_ua_history` 增加容量治理方案，至少补齐保留期、清理批次与观测指标，避免该表在高流量下长期膨胀
- [ ] 记录每轮删除条数、耗时、失败重试信息

#### 涉及文件

- `service/cron_fingerprint.go`
- `model/fingerprint.go`
- `model/behavior_profile.go`

#### 预期收益

- 避免大批量删除带来的锁放大
- 清理过程对线上请求更友好

#### 风险

- 积压严重时清理追赶周期变长

#### 验收标准

- [ ] 清理任务可以分批完成
- [ ] 清理期间服务端无明显抖动

---

## 6. P1：进入 schema 优化与容量治理

## 6.1 P1 目标
在 P0 稳定后，再通过索引、字段瘦身、冷热分层继续压缩读写成本和数据库占用。

### Task P1-1：按真实查询路径补复合索引

**是否改 schema**：是

#### 实施内容

- [ ] 为 `user_fingerprints` 增加更贴近读取模式的复合索引
  - 重点方向：`(user_id, created_at)`
- [ ] 为 `account_links` 增加后台列表与 pair 查询相关索引
  - 重点方向：`(status, confidence, created_at)`
  - 保证 pair 唯一键语义清晰
- [ ] 为 `user_device_profiles`、`user_temporal_profiles` 补充高频筛选索引

#### 涉及文件

- `model/fingerprint_migration.go`
- `model/fingerprint.go`
- `model/account_link.go`
- `model/main.go`

#### 预期收益

- 提升高频查询速度
- 降低排序、过滤、分页成本

#### 风险

- 索引会增加写放大与迁移期间负担

#### 验收标准

- [ ] 三库迁移可执行
- [ ] 主要查询 plan 明显改善
- [ ] 后台与 cron 查询耗时下降

---

### Task P1-2：瘦身 `account_links.match_details`

**是否改 schema**：可选，优先以兼容方式落地

#### 实施内容

- [ ] 将 `match_details` 从“完整明细常驻”调整为“摘要优先”
- [ ] 列表接口只依赖摘要字段，不依赖完整文本 JSON
- [ ] 完整详情按需实时计算或单独存储

#### 涉及文件

- `model/account_link.go`
- `service/link_analyzer.go`
- `service/association_query.go`
- `controller/admin_fingerprint.go`

#### 预期收益

- 降低 `account_links` 表体积
- 提升列表读取效率

#### 风险

- 详情页可能增加一次额外加载或现算

#### 验收标准

- [ ] `account_links` 平均行大小下降
- [ ] 列表页不再依赖重 JSON 文本

---

### Task P1-3：原始流水表热数据保留，长期查询转向设备档案/聚合结果

**是否改 schema**：否 / 可选

#### 实施内容

- [ ] 明确 `user_fingerprints` 仅保留热数据窗口（如 30/60/90 天）
- [ ] 管理后台优先查 `user_device_profiles` 与聚合结果，而不是默认依赖历史流水
- [ ] 根据业务容忍度重新评估保留天数

#### 涉及文件

- `common/fingerprint_config.go`
- `service/cron_fingerprint.go`
- `controller/admin_fingerprint.go`
- `service/association_query.go`

#### 预期收益

- 持续控制主表体积
- 降低后台查旧流水的概率

#### 风险

- 部分历史复核路径依赖旧流水时，需要页面提示或切换查询路径

#### 验收标准

- [ ] 后台默认流程不再依赖长期保留的 `user_fingerprints`
- [ ] 热数据窗口缩短后功能无明显退化

---

### Task P1-4：Temporal profile 只刷新活跃用户

**是否改 schema**：否

#### 实施内容

- [ ] 将 `RefreshTemporalProfilesCron()` 从“全量用户刷新”改为“最近有新增指纹的用户刷新”
- [ ] 引入活跃判定窗口，避免静默用户反复计算

#### 涉及文件

- `service/temporal_analyzer.go`
- `service/cron_fingerprint.go`
- `model/fingerprint.go`

#### 预期收益

- 降低小时级 cron 的无效计算
- 减少 `user_temporal_profiles` 与 `user_sessions` 的更新压力

#### 风险

- 静默用户画像刷新不及时，但业务价值有限

#### 验收标准

- [ ] temporal cron 总耗时明显下降
- [ ] 活跃用户画像仍保持及时更新

---

## 7. P2：结构性优化与长期容量方案

## 7.1 P2 目标
在 P0/P1 稳定后，把高频后台查询与长期存储进一步解耦，避免系统再次被数据量拖回原状。

### Task P2-1：关联结果物化快照

**是否改 schema**：是

#### 实施内容

- [ ] 新增关联结果快照/物化表，保存用户 TopN 关联摘要
- [ ] 后台列表优先查快照，实时计算作为兜底
- [ ] 增量扫描完成后只更新受影响用户快照

#### 涉及文件

- `service/cron_fingerprint.go`
- `service/association_query.go`
- `model/account_link.go`
- 新增快照模型/迁移文件

#### 预期收益

- 后台查询从“现算为主”转成“读取物化结果为主”
- p95/p99 延迟进一步下降

#### 风险

- 快照存在短时间滞后

#### 验收标准

- [ ] 常见后台列表查询无需重算全部候选
- [ ] 快照更新链路稳定可回滚

---

### Task P2-2：冷数据归档

**是否改 schema**：是

#### 实施内容

- [ ] 为 `user_fingerprints` 增加归档表或归档策略
- [ ] 将超过热数据窗口的记录迁移到冷表
- [ ] 默认后台只查热表，必要时显式查归档

#### 涉及文件

- `model/fingerprint_migration.go`
- `model/fingerprint.go`
- `service/cron_fingerprint.go`
- `controller/admin_fingerprint.go`

#### 预期收益

- 保持在线主表体积稳定
- 长期容量可预测

#### 风险

- 归档查询路径更复杂

#### 验收标准

- [ ] 主表增长速度显著放缓
- [ ] 历史查询仍有明确兜底路径

---

### Task P2-3：长期保留数据进一步摘要化

**是否改 schema**：视实现而定

#### 实施内容

- [ ] 对长期保留的行为与关联明细进一步做摘要化
- [ ] 保证长期保留的是“足够支撑复核的证据摘要”，不是完整高维原始文本

#### 涉及文件

- `model/behavior_profile.go`
- `model/account_link.go`
- 相关后台展示与导出逻辑

#### 预期收益

- 进一步降低长期存储成本
- 控制 text/json 字段持续膨胀

#### 风险

- 过度摘要可能削弱历史复核细节

#### 验收标准

- [ ] 长期表平均行大小可控
- [ ] 管理端仍可解释关联结论

---

## 8. 数据库占用评估方法

### 8.1 基线统计

- [ ] 按表统计总行数
- [ ] 按表统计最近 7 / 30 天增长量
- [ ] 分离数据体积与索引体积

### 8.2 单位成本采样

- [ ] 抽样计算 `user_fingerprints` 单行平均字节
- [ ] 抽样计算 `account_links` 单行平均字节
- [ ] 抽样计算 `user_sessions` / `user_temporal_profiles` 平均字节

### 8.3 增长模型

推荐采用下式作为估算口径：

`月增长量 = 日活用户 × 人均日有效写入次数 × 单行平均字节 × 30 × 索引放大系数`

其中：

- **人均日有效写入次数**：去重后的真实落库次数
- **单行平均字节**：按库实际采样得到
- **索引放大系数**：按各库实际情况估算，不凭感觉写死

### 8.4 评估输出

- [ ] 输出优化前预测月增长量
- [ ] 输出 P0 后预测月增长量
- [ ] 输出 P1 后预测月增长量
- [ ] 记录预测与实际偏差，按周更新模型

---

## 9. 测试与发布要求

## 9.1 功能正确性

- [ ] 现有关联结果不发生明显异常回退
- [ ] 关键强信号（PersistentID / ETag / WebRTC / JA4 等）仍然正常工作
- [ ] 后台关联、详情、设备档案、temporal / network 展示可正常使用

## 9.2 性能验证

- [ ] 对比优化前后的写入吞吐与耗时
- [ ] 对比全量扫描单轮执行时间
- [ ] 对比关联页接口 p50 / p95 / p99
- [ ] 对比主要表的日增长量

## 9.3 三库兼容

- [ ] SQLite 验证迁移与查询正确性
- [ ] 修复并验证 SQLite 下 `CountUniqueUAs()` 不可使用 `CONCAT` 的兼容问题
- [ ] MySQL 验证索引与批量删除策略
- [ ] PostgreSQL 验证迁移、索引与 JSON/TEXT 路径兼容性

## 9.4 发布策略

- [ ] P0 先用配置开关灰度
- [ ] 每项优化独立可回滚
- [ ] 先上线观测，再继续推进下一阶段

---

## 10. 实施顺序建议

### 第 1 周

- [ ] 完成 Baseline 指标采集
- [ ] 完成 P0-1 写入去重
- [ ] 完成 P0-5 缓存键细化

### 第 2 周

- [ ] 完成 P0-2 全量扫描预算化
- [ ] 完成 P0-3 候选发现预算化
- [ ] 完成 P0-4 后台懒加载拆分
- [ ] 完成 P0-6 批量清理改造

### 第 3~4 周

- [ ] 完成 P1-1 索引迁移
- [ ] 完成 P1-2 `match_details` 瘦身
- [ ] 完成 P1-3 热数据保留策略调整
- [ ] 完成 P1-4 temporal 活跃刷新

### 第 5 周以后

- [ ] 评估是否进入 P2
- [ ] 若后台查询与库体积仍继续增长，再推进物化快照与冷归档

---

## 11. 结论

本次实施计划的核心不是继续堆更多指纹维度，而是先解决当前系统的三类根问题：

1. **原始流水写入过多**
2. **全量 pair 扫描扩展性差**
3. **后台查询依赖现算与多次补查**

只要 P0 做扎实，服务器压力和数据库增长都会先明显缓和；P1 再补索引与容量治理，系统才会进入可长期维护的状态；P2 只在数据规模继续上升时再做，不提前过度设计。
