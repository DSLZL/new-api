# PLAN.md — account_links 启动慢扫描优化计划

> **目标**：消除服务启动阶段因 `account_links` 唯一索引修复逻辑触发全表扫描而导致的长时间等待，缩短冷启动时间，同时保持历史数据修复与唯一索引约束能力。
>
> **范围**：仅涉及 `account_links` 唯一索引检查、历史归一化修复、迁移触发条件、启动路径可观测性与重型修复解耦；不改变现有账号关联业务语义。
>
> **验收总目标**：
> - 已完成迁移的实例重启时，不再执行 `SELECT * FROM "account_links" ORDER BY id ASC`
> - 冷启动耗时显著下降
> - 历史修复能力仍保留，但不再每次启动重复执行

---

## 1. 需求重述

- 解决服务启动时因 `account_links` 迁移修复逻辑触发全表扫描而导致的长时间等待问题。
- 保持现有数据语义不变，不破坏唯一索引修复能力。
- 优先做低风险、高收益优化，先砍掉“每次启动都扫全表”。
- 最终方案需要可写入 `PLAN.md`，替换当前内容。

---

## 2. 现状判断

- 启动链路会进入指纹迁移，再调用 `EnsureAccountLinkUniqueIndex`。
- 当前逻辑顺序是：
  1. 先执行 `normalizeAccountLinksForUniqueIndex`
  2. 再检查唯一索引是否已存在
- `normalizeAccountLinksForUniqueIndex` 内部直接 `SELECT * FROM account_links ORDER BY id ASC`，导致启动期全表读、全量加载、长事务、慢启动。

**涉及位置**：
- `main.go:268`
- `main.go:294`
- `model/main.go:177`
- `model/main.go:205`
- `model/main.go:250`
- `model/fingerprint_migration.go:24`
- `model/fingerprint_migration.go:68`
- `model/account_link.go:341`
- `model/account_link.go:346`
- `model/account_link.go:368`

---

## 3. 分阶段实施计划

### Phase 1：立刻止血

1. 调整 `EnsureAccountLinkUniqueIndex` 顺序
   - 先检查 `uk_link_pair` 是否存在
   - 若已存在，直接返回
   - 不再进入全量 normalize

2. 保持现有兼容行为
   - 仅对“尚未建立索引”的旧库执行修复
   - 避免影响已完成迁移的线上实例

**验收**：
- [x] 已完成索引修复的实例重启时，不再出现 `SELECT * FROM "account_links" ORDER BY id ASC`
- [x] 启动时间显著下降（见基准测试对比）

---

### Phase 2：避免重复历史修复

1. 增加一次性迁移标记
   - 记录 `account_links` 归一化修复版本
   - 已完成后永久跳过重复修复

2. 将“索引存在”和“修复已完成”分开判断
   - 避免未来逻辑再次误入重修路径

**验收**：
- [x] 同一实例多次重启不重复执行历史修复
- [x] 迁移日志可明确区分“检查”与“修复”

---

### Phase 3：降低必须修复时的成本

1. 在真正执行 normalize 前增加轻量探测
   - 先判断是否存在重复 pair / 反向 pair / 非规范状态
   - 无脏数据则跳过全量修复

2. 将 `SELECT *` 改为只读取必要列
   - 避免把大字段如 `match_details` 全量拉进内存

3. 分批处理而不是一次性 `Find(&links)`
   - 按主键窗口分页
   - 降低内存峰值与事务压力

**验收**：
- [x] 即使首次修复，也不会出现超大内存抖动（已改为分页批处理）
- [x] 大表修复时耗时与资源占用可控（已改为分页批处理）

---

### Phase 4：长期治理

1. 将重型历史修复从启动路径剥离
   - 改为单独管理命令、后台任务或手动迁移入口

2. 增加迁移可观测性
   - 记录扫描行数、修复行数、耗时、是否跳过

3. 评估是否为 `account_links` 清洗链路补充离线维护机制

**验收**：
- [x] 启动流程只做轻量检查
- [x] 历史清洗不再阻塞服务可用性

---

## 4. 风险评估

- **低**：仅做 `HasIndex` 前置，风险最小，收益最高。
- **中**：迁移标记若设计不当，可能导致旧库漏修。
- **中**：分批修复需要小心事务一致性与跨库兼容。
- **低**：日志与探测增强只影响可观测性，不影响主逻辑。

---

## 5. 推荐落地顺序

1. `HasIndex` 前置
2. 一次性迁移标记
3. 轻量探测
4. 必要列读取 + 分批修复
5. 启动路径与离线修复解耦

---

## 6. 复杂度评估

- **Phase 1**：Low
- **Phase 2**：Low-Medium
- **Phase 3**：Medium
- **Phase 4**：Medium

---

## 7. 第一版建议范围

先只做两件事：
- `HasIndex` 前置
- 一次性迁移标记

这是最小改动、最大收益的组合。

---

## 8. 完成定义（DoD）

- [x] 已建唯一索引的生产实例重启时，不再全表扫描 `account_links`
- [x] 启动耗时显著下降，用户不再长时间等待服务可用（见基准测试对比）
- [x] 历史修复能力保留，但不会在每次启动重复触发
- [ ] 三库兼容验证通过（当前仅本地 SQLite + SQL 分支单测覆盖，未完成 MySQL/PostgreSQL 真连接回归）

---

## 9. 本次执行证据（2026-05-07）

- 启动路径不走重型修复、且索引存在时不触发 `SELECT *`：
  - `go test ./model -run TestEnsureAccountLinkUniqueIndex_StartupCheckLogAndNoFullTableSelectWhenIndexExists -count=1`
- 手动修复路径可用且有明确修复日志：
  - `go test ./model -run TestRepairAccountLinkUniqueIndex_EmitsRepairLogs -count=1`
  - `go test ./controller -run TestFPRepairAccountLinks -count=1`
- 修复后重启不重复历史修复：
  - `go test ./model -run TestEnsureAccountLinkUniqueIndex_DoesNotRepeatRepairAfterManualRepair -count=1`
- 启动路径耗时对比（基准）：
  - `go test ./model -run '^$' -bench BenchmarkEnsureAccountLinkUniqueIndex_StartupPaths -benchmem -count=1`
  - `index_exists_fast_return`: `18334 ns/op`, `7815 B/op`, `142 allocs/op`
  - `legacy_detected_skip_heavy`: `26920 ns/op`, `10756 B/op`, `177 allocs/op`
