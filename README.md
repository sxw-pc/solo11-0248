# 运行时隔离契约庭

离线模拟多租户容器平台的隔离档案发布、工作负载沙箱准入和系统调用违规处置。SQLite 保存档案及节点功能、租户风险上限与例外批准、绑定与启动回执、违规证据及隔离解封。模拟器不接入真实容器运行时或内核。

```sh
python -m sandcontract demo --db demo.sqlite
python -m sandcontract replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个入口 `profile`、`admit`、`incident` 分别提供正常和失败 JSON fixture。正常流程从档案和节点能力开始，经双角色例外批准、节点分配与启动确认，再由两个独立违规来源冻结租户；新档案和节点重置回执齐备才解封。`replay` 将原始事件重新执行并逐表核对状态。单入口命令形如 `python -m sandcontract profile --db state.sqlite --fixture fixtures/profile_normal.json`。跨入口样例按顺序使用同一新数据库。
