# 运行时隔离契约庭

离线模拟多租户容器平台的隔离档案发布、工作负载沙箱准入和系统调用违规处置。SQLite 保存档案及节点功能、租户风险上限与例外批准、绑定与启动回执、违规证据及隔离解封。模拟器不接入真实容器运行时或内核。

```sh
python -m sandcontract demo --db demo.sqlite
python -m sandcontract replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个入口 `profile`、`admit`、`incident` 分别提供正常和失败 JSON fixture。正常流程从档案和节点能力开始，经双角色例外批准、节点分配与启动确认，再由两个独立违规来源冻结租户；新档案和节点重置回执齐备才解封。`replay` 将原始事件重新执行并逐表核对状态。单入口命令形如 `python -m sandcontract profile --db state.sqlite --fixture fixtures/profile_normal.json`。跨入口样例按顺序使用同一新数据库。

## 双边结算 `sandcontract/usage_settlement.py`

`usage.py` 的逐页求和只是临时费用；`usage_settlement.py` 在同一 SQLite 事件库上补齐供应商应付与客户可收两本账，并以 `settlement`（或 `usage_settlement`）子系统接入 `store.execute` / `replay`。

- 设备计数按 `(chassis, generation)` 的单调区间求增量；自然指纹去重代理重发，拒绝计数器回卷、同代区间重叠与跨代复用同一墙钟窗口。供应商账单占用计量区间，同一物理秒至多一张有效账单、一笔有效付款；换供应商须先追加账单冲正，银行退票只追加 `bounced` 事件，再用新付款凭证重试，绝不重付。
- 客户发票只来自独立执行回执、未落入不可收费时段且合同允许 CPU 计费的秒数；`binding` 仍为 active 或代理页标签本身不产生费用。隔离后内核空转（`isolated_kernel`）、迁机双跑（`migration_overlap`）与合同禁计秒数进入单列责任。
- 无法厘清的差额（如换代共享临时槽的 30 秒、候选仅甲/乙）不做 15/15 均摊，而是携带原始窗口与候选 workload 进入 `us_suspense`。甲方案开无争议发票、平台准备金足额付供应商、差额挂待追收；乙方案只发可核验用量告知、以预签共享风险保证金垫付争议秒数、平台支付其余部分，待迟到设备回单厘清后再开正式发票并在收讫后退还保证金。方案一经执行即互斥，退票与补证交错也不能改选。
- 发票、贷记通知、供应商账单/付款、签收与迟到归属证明全部只追加；旧凭证金额不被 UPDATE，更正以贷记/冲正新单表达。

验收：`python -B -m unittest discover -s tests -q`，其中 `tests/test_usage_settlement.py` 覆盖代次回卷、迁机重叠、代理双报、隔离后仍耗时、银行退票（供应商与客户两侧）、客户贷记、客户签收、迟到执行证明、甲乙方案互斥与全量事件回放。

