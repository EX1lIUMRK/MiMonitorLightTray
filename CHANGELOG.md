# Changelog

## 1.6.0

English, Russian, and Chinese. The language is chosen in **Settings → General settings** and in the tray menu: **System default**, **English**, **Русский**, **中文**. The first run, and **System default**, follow the Windows display language (`ru` → Russian, `zh` → Chinese, anything else → English). A tray choice applies and is saved immediately. The settings list previews the language; **Save** keeps it and **Cancel** restores the previous one. Existing configs gain `"language": "auto"`.

Security and build changes in this version:

- The Windows executable is built with Python 3.12 (OpenSSL 3), not CPython 3.10.11 / OpenSSL 1.1.1t. The 3.10 packaging pin was only to match a local virtualenv's file size.
- Runtime dependencies are pinned with hashes in `requirements/lock.txt`. The previous unpinned set bundled certifi 2026.07.22, Pillow 12.3.0, urllib3 2.7.0, and setuptools 65.5.0.
- Device tokens in `%APPDATA%\MiMonitorLightTray\config.json` are sealed with Windows DPAPI for the current user. Older plaintext configs are rewritten on the next launch. The file ACL is limited to the current user.
- A new IP from UDP discovery is saved only after the lamp answers an authenticated miio `info()` with the stored token and the same device id.
- Debug logs redact Xiaomi `serviceToken`, `ssecurity`, `passToken`, cookies, and 32-character hex tokens.
- The update check is notify-only: one HTTPS request to `api.github.com` with a timeout and no redirects. It opens a GitHub release page in the browser and does not download or run an executable.
- CI on `windows-latest` runs pytest, ruff, bandit, and pip-audit, uploads the exe plus `SHA256SUMS`, and attests build provenance. A `v*` tag publishes a GitHub Release.

The unmerged upstream `web` branch (an HTTP server on `0.0.0.0:8765` with authentication disabled) is not part of this tree.
