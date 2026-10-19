# 后台 GitHub Actions 自动部署

推送 `main` 后，工作流先在临时数据库中运行 `tests/test_ops_api.py`，并从主应用仓库检出其当前 `main` 代码作为跨进程契约依赖。测试通过后才部署后台 API 与控制台页面。Pull request 不访问生产密钥，也不会连接线上服务。

仓库使用受 `main` 分支限制的 `production` GitHub Environment，并配置 `QINGSU_CI_SSH_KEY` Secret。私钥对应服务器上的专用 `qingsu-ci` 账号。服务器入口只接受后台发布目标，校验压缩包 SHA-256 后备份线上文件、原子替换、重启 `qingsu-ops`，并检查健康 API 和受认证的 `/ops/` 页面；检查失败时恢复旧文件。

SSH 主机指纹固定在 `.github/deploy_known_hosts`。服务器文件备份保留在 `/opt/qingsu/backups`。
