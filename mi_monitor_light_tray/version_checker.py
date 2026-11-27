"""GitHub Release version checker for automatic update notifications.

The checker only reads the public releases API and returns a browser URL.
It does not download or run an executable.
"""

from __future__ import annotations

import logging
import re
import threading
import urllib.parse
from typing import Optional, Tuple
from pathlib import Path

import requests

log = logging.getLogger(__name__)

# This fork publishes its own builds. Notifications point here, not upstream.
PROJECT_REPO = "EX1lIUMRK/MiMonitorLightTray"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_HOSTS = {"github.com", "www.github.com"}


def get_current_version() -> str:
    """Get the current version from pyproject.toml or package metadata.

    Returns:
        Version string like "1.3.9"
    """
    # Try to get version from installed package metadata first (works in EXE)
    try:
        from importlib.metadata import version
        return version("mi-monitor-light-tray")
    except Exception:
        pass

    # Fallback: try reading pyproject.toml with tomllib/tomli
    try:
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                tomllib = None

        if tomllib:
            project_root = Path(__file__).parent.parent
            toml_path = project_root / "pyproject.toml"

            if toml_path.exists():
                with open(toml_path, "rb") as f:
                    data = tomllib.load(f)
                    return data.get("project", {}).get("version", "unknown")
    except Exception as exc:
        log.debug("Failed to read version from pyproject.toml: %s", exc)

    # Last resort: manual parsing
    return _parse_version_manually()


def _parse_version_manually() -> str:
    """Manually parse version from pyproject.toml without toml library."""
    try:
        project_root = Path(__file__).parent.parent
        toml_path = project_root / "pyproject.toml"

        if toml_path.exists():
            content = toml_path.read_text(encoding="utf-8")
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("version"):
                    # Extract version from: version = "1.3.2"
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        version = parts[1].strip().strip('"').strip("'")
                        return version
    except Exception as exc:
        log.debug("Manual version parsing failed: %s", exc)

    return "unknown"


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse version string to tuple for comparison.

    Args:
        version_str: Version like "1.3.2" or "v1.3.2"

    Returns:
        Tuple like (1, 3, 2)
    """
    version_str = version_str.strip().lstrip("v")
    parts: list[int] = []
    try:
        for part in version_str.split("."):
            digits = ""
            for char in part:
                if char.isdigit():
                    digits += char
                else:
                    break
            if not digits:
                break
            parts.append(int(digits))
    except (ValueError, AttributeError):
        return (0,)
    return tuple(parts) or (0,)


def release_page_url(url: str, repo: str = PROJECT_REPO) -> Optional[str]:
    """Return a https GitHub release page, or None if ``url`` is not one."""
    if not _REPO_RE.fullmatch(repo):
        return None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _GITHUB_HOSTS:
        return None
    prefix = f"/{repo}"
    if parsed.path != prefix and not parsed.path.startswith(prefix + "/"):
        return None
    return urllib.parse.urlunparse(parsed._replace(query="", fragment=""))


def check_for_updates(
    repo: str = PROJECT_REPO,
    timeout: float = 5,
) -> Optional[dict]:
    """Check GitHub Releases for a newer version and return a browser link.

    The response is notify-only: no asset is downloaded and nothing is executed.
    Redirects are refused so the request cannot leave api.github.com.
    """
    if not _REPO_RE.fullmatch(repo):
        log.warning("Refusing update check for unexpected repository name")
        return None

    current_version = get_current_version()
    if current_version == "unknown":
        log.warning("Cannot determine current version, skipping update check")
        return None

    url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "MiMonitorLightTray",
    }
    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=(3.05, timeout),
            allow_redirects=False,
            verify=True,
        )
        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            log.warning("Update check refused a redirect")
            return None
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            log.warning("Update check got an unexpected response")
            return None
        latest_version = str(data.get("tag_name") or "").lstrip("v")
        if not latest_version:
            log.debug("No release version found in API response")
            return None

        current_tuple = parse_version(current_version)
        latest_tuple = parse_version(latest_version)
        if latest_tuple <= current_tuple:
            log.debug("Already on latest version: %s", current_version)
            return None

        page = release_page_url(str(data.get("html_url") or ""), repo)
        if page is None:
            page = f"https://github.com/{repo}/releases/latest"
        log.info("Update available: %s -> %s", current_version, latest_version)
        body = data.get("body") or ""
        if not isinstance(body, str):
            body = ""
        return {
            "version": latest_version,
            "url": page,
            "body": body[:4000],
        }
    except requests.RequestException as exc:
        log.debug("GitHub API request failed: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        log.warning("Update check failed: %s", exc)
        return None


class VersionChecker:
    """Background version checker that runs on a separate thread."""

    def __init__(self, repo: str = PROJECT_REPO):
        self.repo = repo
        self._update_info: Optional[dict] = None
        self._checked = False

    def check_async(self) -> None:
        """Start an async check in the background."""
        thread = threading.Thread(target=self._check_thread, daemon=True)
        thread.start()

    def _check_thread(self) -> None:
        """Background thread that performs the check."""
        self._update_info = check_for_updates(self.repo)
        self._checked = True

    def get_update_info(self) -> Optional[dict]:
        """Get the cached update info, if any.

        Returns:
            Update info dict if newer version available, None otherwise
        """
        return self._update_info

    def has_checked(self) -> bool:
        """Check if the async check has completed."""
        return self._checked
