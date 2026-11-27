# v1.6.0

界面支持中文、English、Русский，并修复 v1.5.4 安全审计里确认过的问题。Windows 安装包改由 Python 3.12 按锁定依赖构建。

**English.** Choose **System default**, **English**, **Русский**, or **中文** in Settings or the tray menu. System default follows the Windows display language. The choice is saved in `config.json` and applies without reinstalling. Device tokens are encrypted with Windows DPAPI, discovery will not save an IP until the lamp answers with the stored token, and the update check only opens a browser page.

**Русский.** Язык выбирается в **Настройках** и в меню трея: **Как в Windows**, **English**, **Русский**, **中文**. По умолчанию используется язык интерфейса Windows. Выбор сохраняется и применяется без переустановки. Ключ устройства шифруется DPAPI, новый IP записывается только после проверки ключом, а проверка обновлений только открывает страницу загрузки в браузере.

## ✨ 界面语言

- 设置 → 全局设置，以及托盘菜单 **Language / Язык / 语言**，四个选项：跟随系统、English、Русский、中文
- 首次运行和「跟随系统」读取 Windows 显示语言：`ru` 俄语，`zh` 中文，其它英语
- 托盘里切换立即生效并写入配置。设置里先预览，**保存**记住，**取消**恢复
- 旧的 `config.json` 自动补上 `"language": "auto"`，设备数据不变

## 🐛 安全

- 打包不再使用 CPython 3.10.11。当初改到 3.10 只是为了让 CI 产物体积和本地 3.10 虚拟环境一致（约少 4MB），不是功能故障。3.10.11 自带的 OpenSSL 1.1.1t 已停止维护。安装包改为 Python 3.12（OpenSSL 3）
- 依赖改为 `requirements/lock.txt` 里的精确版本和哈希。此前 `>=` 约束把 certifi 2026.07.22（含已不受信任的 emSign ECC Root CA - G3，GHSA-6q48-6c7w-9gw2）、Pillow 12.3.0、urllib3 2.7.0、setuptools 65.5.0 打进了 exe
- 设备 Token 用当前 Windows 用户的 DPAPI 加密后写入配置，旧的明文配置在下次启动时自动迁移。配置文件 ACL 收紧为仅当前用户。换 Windows 帐户后需要重新填写 Token
- 局域网广播发现到的新 IP，必须用已保存的 Token 完成一次 miio `info()`，且设备 ID 一致，才会写入配置
- `--debug` 不再记录小米账号响应里的 `serviceToken`、`ssecurity`、`passToken`、Cookie 和 32 位十六进制 Token
- 更新检查只访问 `https://api.github.com`（超时、不跟随重定向），然后在浏览器打开 Release 页面。程序不下载、不运行安装包

## 🧹 构建

- GitHub Actions 在 `windows-latest` 上跑 pytest、ruff、bandit、pip-audit，上传 exe 和 `SHA256SUMS`，并生成构建来源证明（artifact attestation）
- 推送 `v*` tag 时创建 GitHub Release，附带 exe 和校验文件
- 上游未合并的 `web` 分支（`0.0.0.0:8765`、无认证的 HTTP 服务）没有进入这个版本

## ⚠️ 请在真机上确认

- 语言：跟随系统、三种语言来回切换、保存和取消
- 原有明文配置升级后灯仍能控制，`config.json` 里的 token 不再是 32 位明文
- 路由器重新分配 IP 后，灯能在认证通过后被重新找到
- 托盘「检查更新」只打开浏览器

[v1.5.4 → v1.6.0 完整变更](https://github.com/EX1lIUMRK/MiMonitorLightTray/compare/v1.5.4...v1.6.0)
