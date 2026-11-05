# r189 视觉模型设置

配对主应用：783d9ccc260f6ccb5dd42207cab8956848c793b7（2.4.1 / 74 / schema16）。

运维台新增“视觉模型”，可保存本机或外部HTTPS视觉API、模型名和密钥，启用或停用，检查连接与模型列表，以及主动上传测试图验证实际识图。配置存在、连接成功、实际图像返回结果是不同状态；退出清除密钥输入与测试结果。

密钥不回显、不写审计；仅当目标和模型相同才允许留空保留。外部目标拒绝私网和重定向；本机固定127.0.0.1:8082/v1。配置由qingsu-ops写入/opt/qingsu/vision-config/vision.json，主应用组只读，后台systemd仅额外放行该目录写入。主应用scripts/provision-vision.py完成首次准备，不覆盖已存在设置。

本机采用Apache-2.0的InternVL3-1B。模型只初步识别种类，营养使用24项USDA参考数据，每项初始100g为待核对假设，不声称从照片称重。实际模型、图片识别边界及正式发布证据见主仓docs/release-r189.md。

本地验证：既有运维42项、最终视觉API6项、真实Chromium5项通过。浏览器模型是明确合成夹具，真实模型在服务器另验。测试配置已强制绑定临时目录，避免写默认服务配置；夹具错配时产生的合成遗留文件已清理。

生产复验追加修复：检查结果默认跟随VISION_CONFIG同目录，避免向root所有的admin目录写入。部署drop-in明确VISION_CHECK路径；API新增默认目录契约，最终本地视觉API6项及浏览器5项通过。

最终发布源码ce007ffa185189ba1da77d72e668bf37ed0add02；[CI42012972420](https://github.com/clowndest-svg/JianZhiSuXingRuanJianHouTai/actions/runs/42012972420)的test/deploy全部成功。生产后台与主应用r42009371148/schema16配对，真实后台7项验收通过：源码与配对检查、配置不回显密钥、UID990原子保存、实际模型连接、实际图片识别及结果状态落盘、原有权限边界。真实应用API11项及线上Chromium5项通过，验收账号全部清理，真实用户仍为2，数据库完整性ok、外键违规0。

运行目录/opt/qingsu/admin继续保持原有权限；仅/opt/qingsu/vision-config目录对后台可写。最终监控正常，加密备份已拉取并隔离恢复验证。已清理原后台工作区6个旧临时目录及服务器过期上传归档，保留真实数据和回退备份。

主应用[最终发布记录](https://github.com/clowndest-svg/JianZhiSuXingRuanJian/blob/main/docs/release-r190.md)包含最终安装包指纹、证据与限制。本地模型每项100g为待核对假设，不能从照片精确称重；实体Android相机/安装未完成设备验收。当前收尾提交仅归档文档，不改变上述已部署源码。
