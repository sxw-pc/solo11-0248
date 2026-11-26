# 运行时隔离契约庭

离线模拟多租户容器平台的隔离档案发布、工作负载沙箱准入和系统调用违规处置。SQLite 保存档案及节点功能、租户风险上限与例外批准、绑定与启动回执、违规证据及隔离解封。模拟器不接入真实容器运行时或内核。

```sh
python -m sandcontract demo --db demo.sqlite
python -m sandcontract replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个入口 `profile`、`admit`、`incident` 分别提供正常和失败 JSON fixture。正常流程从档案和节点能力开始，经双角色例外批准、节点分配与启动确认，再由两个独立违规来源冻结租户；新档案和节点重置回执齐备才解封。`replay` 将原始事件重新执行并逐表核对状态。单入口命令形如 `python -m sandcontract profile --db state.sqlite --fixture fixtures/profile_normal.json`。跨入口样例按顺序使用同一新数据库。

## 客户可验证数据删除（`erasure` / `retention`）

`retention` 在确认的启动回执（`starts`）之后把归档号登记为 provisional；未启动不能登记。`erasure` 把删除范围从沙箱写入日志、归档页、快照与对象副本追到物理块（含控制器重映射区）和封装钥的全部副本（机房、缓存、离线灾备），证据写入数据库之外的文件系统保管库，跨库与文件系统可经事件回放核对。

同一现场支持两种完整删除结果，均不损害共享底层块的另一租户：

- `physical`：先把共享压缩块中另一租户的内容重写到其专属块，封存保留令覆盖的页（独立封存钥与隔离副本），逐介质擦除租户其余页并核验重映射区回单，再销毁封装钥全部副本（含离线灾备）；物理占用立即释放。
- `crypto`：把租户余下页隔离为仅由本租户封装钥控制、他租户钥无法解开的密文，逐份销毁该钥的全部托管、缓存与离线副本；原密文暂占空间，待带同样控制器回单的正常介质回收（`reclaim`）再释放。

任何控制器回单、离线灾备钥销毁证明或封存证据缺失、被篡改，均不签发完成证书。法律保留按精确客户、字节范围与期限隔离：保留期内只发 partial 证书，保留令到期（`release_hold`）后擦除保留页、销毁封存钥并追加撤回旧证书；已封存事故证据转为 retained_evidence 不被覆盖。重复删除返回 `already_erased`，中断后的作业只能 `resume_required` 并从最后一个有证据的阶段恢复。

