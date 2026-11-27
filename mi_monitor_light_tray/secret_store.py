"""Protect device tokens at rest.

On Windows the token is sealed with DPAPI (CryptProtectData) for the current
user, plus a fixed application entropy so other programs cannot unprotect it
by calling CryptUnprotectData alone. Existing plaintext configs still load.
The next save rewrites them as ``dpapi:v1:`` values.

The config file's ACL is also reduced to the current user. DPAPI is the
control that matters if an administrator can still read the file; the ACL
stops other accounts on the machine from reading it directly.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Optional, Protocol

log = logging.getLogger(__name__)

_DPAPI_PREFIX = "dpapi:v1:"
# Not a secret. It binds the blob to this program so a casual
# CryptUnprotectData from another process running as the same user fails.
_DPAPI_ENTROPY = b"MiMonitorLightTray.token.v1"


class TokenCipher(Protocol):
    def protects(self) -> bool: ...

    def is_sealed(self, stored: str) -> bool: ...

    def protect(self, token: str) -> str: ...

    def unprotect(self, stored: str) -> str: ...


class PlaintextCipher:
    """Used outside Windows, where DPAPI does not exist.

    The tray app is Windows-only. Unit tests inject their own cipher.
    """

    def protects(self) -> bool:
        return False

    def is_sealed(self, stored: str) -> bool:
        return False

    def protect(self, token: str) -> str:
        return token

    def unprotect(self, stored: str) -> str:
        return stored


class DpapiTokenCipher:
    def protects(self) -> bool:
        return True

    def is_sealed(self, stored: str) -> bool:
        return stored.startswith(_DPAPI_PREFIX)

    def protect(self, token: str) -> str:
        if not token or self.is_sealed(token):
            return token
        blob = _dpapi_protect(token.encode("utf-8"))
        return _DPAPI_PREFIX + base64.b64encode(blob).decode("ascii")

    def unprotect(self, stored: str) -> str:
        if not stored or not self.is_sealed(stored):
            return stored
        raw = base64.b64decode(stored[len(_DPAPI_PREFIX):])
        return _dpapi_unprotect(raw).decode("utf-8")


_override: Optional[TokenCipher] = None
_PLAIN = PlaintextCipher()
_DPAPI = DpapiTokenCipher()


def use_cipher(cipher: Optional[TokenCipher]) -> Optional[TokenCipher]:
    """Install a process-wide cipher. ``None`` restores the platform default."""
    global _override
    previous = _override
    _override = cipher
    return previous


def get_cipher() -> TokenCipher:
    if _override is not None:
        return _override
    if sys.platform == "win32":
        return _DPAPI
    return _PLAIN


def _data_blob_type():
    import ctypes

    cached = getattr(_data_blob_type, "cls", None)
    if cached is None:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        _data_blob_type.cls = DATA_BLOB
        cached = DATA_BLOB
    return cached


def _blob(data: bytes):
    import ctypes

    data_blob = _data_blob_type()
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = data_blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def _free_blob(blob) -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def _dpapi_protect(data: bytes) -> bytes:
    import ctypes

    data_blob = _data_blob_type()
    in_blob, in_buffer = _blob(data)
    entropy_blob, entropy_buffer = _blob(_DPAPI_ENTROPY)
    out_blob = data_blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(data_blob),
        ctypes.c_wchar_p,
        ctypes.POINTER(data_blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(data_blob),
    ]
    crypt32.CryptProtectData.restype = ctypes.c_int
    # CRYPTPROTECT_UI_FORBIDDEN: never pop a dialog from the tray process.
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "MiMonitorLightTray",
        ctypes.byref(entropy_blob),
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    del in_buffer, entropy_buffer
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _free_blob(out_blob)


def _dpapi_unprotect(data: bytes) -> bytes:
    import ctypes

    data_blob = _data_blob_type()
    in_blob, in_buffer = _blob(data)
    entropy_blob, entropy_buffer = _blob(_DPAPI_ENTROPY)
    out_blob = data_blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(data_blob),
        ctypes.c_void_p,
        ctypes.POINTER(data_blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(data_blob),
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x01,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    del in_buffer, entropy_buffer
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _free_blob(out_blob)


def _current_user_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        length = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        if length.value <= 0:
            raise ctypes.WinError(ctypes.get_last_error())
        raw = ctypes.create_string_buffer(length.value)

        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

        class TOKEN_USER(ctypes.Structure):
            _fields_ = [("User", SID_AND_ATTRIBUTES)]

        if not advapi32.GetTokenInformation(token, 1, raw, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        user = ctypes.cast(raw, ctypes.POINTER(TOKEN_USER)).contents
        sid_out = ctypes.c_void_p()
        advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        if not advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid_out)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(sid_out)
        finally:
            kernel32.LocalFree(sid_out)
    finally:
        kernel32.CloseHandle(token)


def _apply_sddl(path: Path, sddl: str) -> None:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sd = ctypes.c_void_p()
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(sd), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        advapi32.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        if not advapi32.GetSecurityDescriptorDacl(
            sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not present.value or not dacl.value:
            raise OSError("security descriptor has no DACL")
        name = ctypes.create_unicode_buffer(str(path))
        advapi32.SetNamedSecurityInfoW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong
        # SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        error = advapi32.SetNamedSecurityInfoW(
            name, 1, 0x4 | 0x80000000, None, None, dacl, None
        )
        if error:
            raise ctypes.WinError(error)
    finally:
        kernel32.LocalFree(sd)


def file_dacl_sddl(path: Path) -> str:
    """Return the file DACL in SDDL. Windows only."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    sd = ctypes.c_void_p()
    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_ulong
    error = advapi32.GetNamedSecurityInfoW(
        str(path), 1, 0x4, None, None, None, None, ctypes.byref(sd)
    )
    if error:
        raise ctypes.WinError(error)
    try:
        rendered = ctypes.c_void_p()
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p,
        ]
        advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        if not advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, 1, 0x4, ctypes.byref(rendered), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(rendered)
        finally:
            kernel32.LocalFree(rendered)
    finally:
        kernel32.LocalFree(sd)


def restrict_private_file(path: Path) -> bool:
    """Best-effort owner-only permissions. Never raises into config save."""
    try:
        if sys.platform == "win32":
            sid = _current_user_sid()
            _apply_sddl(path, f"D:P(A;;FA;;;{sid})")
        else:
            os.chmod(path, 0o600)
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                log.warning("Config %s is still group/world accessible (mode %o)", path, mode)
                return False
        return True
    except Exception:  # noqa: BLE001
        log.exception("Could not restrict permissions on %s", path)
        return False
