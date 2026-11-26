# 运行时隔离契约庭

离线模拟多租户容器平台的隔离档案发布、工作负载沙箱准入和系统调用违规处置。SQLite 保存档案及节点功能、租户风险上限与例外批准、绑定与启动回执、违规证据及隔离解封。模拟器不接入真实容器运行时或内核。

```sh
python -m sandcontract demo --db demo.sqlite
python -m sandcontract replay --db demo.sqlite
python -m unittest discover -s tests -v
```

三个入口 `profile`、`admit`、`incident` 分别提供正常和失败 JSON fixture。正常流程从档案和节点能力开始，经双角色例外批准、节点分配与启动确认，再由两个独立违规来源冻结租户；新档案和节点重置回执齐备才解封。`replay` 将原始事件重新执行并逐表核对状态。单入口命令形如 `python -m sandcontract profile --db state.sqlite --fixture fixtures/profile_normal.json`。跨入口样例按顺序使用同一新数据库。

`regulatory` 子系统（`sandcontract/regulatory_delivery.py`）在事故建案后制作监管交付件：调取令固定时间窗、调用类别、签收机构、第三方租户遮蔽范围与保存期限；原始探针包、节点代次、绑定档案摘要、启动回执、违规报告和内核隔离回单汇入同一条 SHA-256 版本链。数据库的 `quarantined` 只代表控制面时刻，内核回单到达前处置状态保持 `control_plane_quarantined_kernel_unconfirmed`，绝不回写“调用时已阻断”。支持两种真实交付：`onsite`（检查员授权/撤权后在受控机房核验，仅取甲的调用序列、24→27 的真实延迟与不可逆遮蔽报告，原包不离平台）和 `hardware`（加密实体加单次解封见证，原混包另有 escrow 密钥，解封视图不含第三方令牌）。文件写入 `0700` Vault，临时文件 `0600` 并原子改名；重跑按业务编号复用，`sweep` 清理回滚遗留的孤儿件，投递按幂等键恰好一次。旧清单签收后只追加 `delta` 差异包、`withdrawal` 撤回令和 `notification` 收件人告知。所有操作经 `execute(db,'regulatory',step)` 入事件日志并可被 `replay` 复验。

