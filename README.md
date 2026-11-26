# 运行时隔离契约庭

离线模拟多租户容器平台的隔离档案发布、工作负载沙箱准入和系统调用违规处置。SQLite 保存档案及节点功能、租户风险上限与例外批准、绑定与启动回执、违规证据及隔离解封。模拟器不接入真实容器运行时或内核。

```sh
python -m sandcontract demo --db demo.sqlite
python -m sandcontract replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个入口 `profile`、`admit`、`incident` 分别提供正常和失败 JSON fixture。正常流程从档案和节点能力开始，经双角色例外批准、节点分配与启动确认，再由两个独立违规来源冻结租户；新档案和节点重置回执齐备才解封。`replay` 将原始事件重新执行并逐表核对状态。单入口命令形如 `python -m sandcontract profile --db state.sqlite --fixture fixtures/profile_normal.json`。跨入口样例按顺序使用同一新数据库。

## 按节点内核能力编译的沙箱契约

`policy_compile` 子系统把档案的显式调用语义（允许/拒绝、参数掩码与位宽、设备权限、网络出站范围、默认拒绝）编译成绑定具体节点内核的过滤器字节，规则先做规范化排序，规则次序与系统调用别名的拼写都不改变许可或摘要。

- 节点登记可携带证明：内核构建摘要、真实系统调用表（语义调用 → 入口号/ABI）、过滤器引擎版本与参数位宽等表达能力。`kernel_version` 字符串只作记录，回移植判定完全基于系统调用表与能力。
- `compile` 逐节点把语义规则映射到该节点的真实入口；掩码允许需要对应的 `arg32/arg64` 能力，无法表达的拒绝或掩码条件以 `entry_absent`/`arg_width_unsupported` 拒绝并留档，绝不静默放宽。产物 `filter_hash` 绑定档案版本摘要、节点代次、证明摘要与实际过滤器字节。
- `load` 只在节点代次匹配且回执字节与编译字节一致时记为 `loaded`；失败回执同样留作审计，节点重建（新 uid/代次）或迟到回执得到 `stale_load_receipt`。
- `assign` 对显式策略档案要求该节点存在 `compiled + loaded` 的同一契约，`start` 还须回报相同 `filter_hash` 并写入 `start_evidence`；客户已确认的启动不被撤销或节点重建重标，旧工作负载保留当时的字节与内核构建证据，新请求不得借用旧内核的兼容结论。`incident release` 对显式策略档案同样要求新档案的已加载契约。

