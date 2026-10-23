# r180 后台生产验收（2026-10-23）

后台业务候选 `6335e3a105aea4374479c96b6063225d52ca55c3`，主应用配对 `f8af43d15df7e234bfe33723d1bbff494ee7fe54` / r39911006231 / schema12。[最终CI](https://github.com/clowndest-svg/JianZhiSuXingRuanJianHouTai/actions/runs/39914786564) test/deploy成功：后台42、安全24、数据7、UX10。

此次配置按版本受控安装，API/HTML经限制入口部署。`qingsu-ops`真实UID990，不在docker组，三项sudo helper可用。代码root:服务组0640；data/uploads 2770，备份root700。Directus日常策略账号只读，明确请求敏感字段被拒；镜像按RepoDigest固定，限768MiB/1CPU。

生产执行发现并修复：旧0700代码降权后不可读；单独可写挂载使快照hardlink报EXDEV；父目录不可遍历被isdir误判成路径不存在，导致备份成功仍报no_snapshot。备份helper现在无参数，仅启动固定Python/脚本的systemd transient service，等待真实退出结果，限制590秒。未给服务账号开放备份目录。

从真实后台API发起备份200/integrity=ok；合成账号注销删除原图及缩略图，pending=0，保留2个真实用户、外键异常0。两个鉴权层分别验证401。只读发布页哈希未算时返回null，避免误报失败；正式APK签名和升级安装需独立验证，不能把ZIP形状称为可安装。

`/opt/qingsu/admin-console/config-release.json`记录实际配置哈希、安装时间及配置备份。运行时revision由`qingsu-ops.service.d/release.conf`提供；**以后发布新后台源码时必须同步此标记并重启**。当前CI只更新API/HTML，未来配置变化不能省略完整安装步骤。配置回退材料位于`/opt/qingsu/backups/admin-config-r180-20261023-144126`；回退代码不能用旧数据库覆盖新增业务。

完整43项范围与未验证边界见主仓`docs/release-r180-final.md`及`docs/release-evidence-r180/`。仅一台服务器，电脑关机后的独立异地副本不可实现；未采购新服务。真机升级、蜂窝通话、外部邮件/告警收件、完整混合容量未宣称通过。本次归档提交仅补此报告，不变更已验收业务候选。
