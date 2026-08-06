"""Human Mimicry Profiles — Comprehensive browser identity profiles.

Phase: HUMAN-MIMICRY-B — Enhanced profiles with Client Hints, platform
consistency, viewport data, and header-to-platform validation.

Covers Chrome 131, Firefox 133, Safari 18.2, Edge 131, Opera 115.
All profiles are read-only static data. No runtime execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import random


class BrowserFamily(str, Enum):
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"
    OPERA = "opera"


class Platform(str, Enum):
    WINDOWS = "Windows"
    MACOS = "macOS"
    LINUX = "Linux"
    ANDROID = "Android"
    IOS = "iOS"
    CHROMEOS = "Chrome OS"


# ── User-Agent strings ────────────────────────────────────────────────

_CHROME_131_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_CHROME_131_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_CHROME_131_LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_CHROME_131_ANDROID = (
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36"
)
_CHROME_131_CR_OS = (
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_CHROME_130_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
_CHROME_129_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
)

_FF_133_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0)"
    " Gecko/20100101 Firefox/133.0"
)
_FF_133_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0)"
    " Gecko/20100101 Firefox/133.0"
)
_FF_133_LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0)"
    " Gecko/20100101 Firefox/133.0"
)
_FF_132_LINUX = (
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0)"
    " Gecko/20100101 Firefox/132.0"
)
_FF_128_ESR = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0)"
    " Gecko/20100101 Firefox/128.0"
)

_SAFARI_18_2_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15"
)
_SAFARI_18_2_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X)"
    " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
)
_SAFARI_18_2_IPAD = (
    "Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X)"
    " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1"
)

_EDGE_131_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)
_EDGE_131_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
)

_OPERA_115_WIN = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0"
)

CHROME_UAS: tuple[str, ...] = (
    _CHROME_130_WIN, _CHROME_131_WIN, _CHROME_131_MAC, _CHROME_131_LINUX,
    _CHROME_131_ANDROID, _CHROME_131_CR_OS, _CHROME_129_WIN,
)
FIREFOX_UAS: tuple[str, ...] = (
    _FF_133_WIN, _FF_133_MAC, _FF_133_LINUX, _FF_132_LINUX, _FF_128_ESR,
)
SAFARI_UAS: tuple[str, ...] = (
    _SAFARI_18_2_MAC, _SAFARI_18_2_IPHONE, _SAFARI_18_2_IPAD,
)
EDGE_UAS: tuple[str, ...] = (_EDGE_131_WIN, _EDGE_131_MAC)
OPERA_UAS: tuple[str, ...] = (_OPERA_115_WIN,)

UA_POOL: dict[BrowserFamily, tuple[str, ...]] = {
    BrowserFamily.CHROME: CHROME_UAS,
    BrowserFamily.FIREFOX: FIREFOX_UAS,
    BrowserFamily.SAFARI: SAFARI_UAS,
    BrowserFamily.EDGE: EDGE_UAS,
    BrowserFamily.OPERA: OPERA_UAS,
}

# ── Client Hints (sec-ch-ua*) ─────────────────────────────────────────

_CHROME_CLIENT_HINTS = {
    "sec-ch-ua": (
        '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"'
    ),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": (
        '"Google Chrome";v="131.0.6778.205", '
        '"Chromium";v="131.0.6778.205", '
        '"Not=A?Brand";v="24.0.0.0"'
    ),
}

_CHROME_MAC_CH = {
    **_CHROME_CLIENT_HINTS,
    "sec-ch-ua-platform": '"macOS"',
    "sec-ch-ua-platform-version": '"15.1.0"',
}

_CHROME_LINUX_CH = {
    **_CHROME_CLIENT_HINTS,
    "sec-ch-ua-platform": '"Linux"',
    "sec-ch-ua-platform-version": '""',
}

_CHROME_ANDROID_CH = {
    "sec-ch-ua": (
        '"Google Chrome";v="131", "Chromium";v="131", "Not=A?Brand";v="24"'
    ),
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-ch-ua-platform-version": '"15.0.0"',
    "sec-ch-ua-arch": '""',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-model": '"Pixel 9 Pro"',
    "sec-ch-ua-full-version-list": (
        '"Google Chrome";v="131.0.6778.200", '
        '"Chromium";v="131.0.6778.200", '
        '"Not=A?Brand";v="24.0.0.0"'
    ),
}

_EDGE_CH = {
    "sec-ch-ua": (
        '"Microsoft Edge";v="131", "Chromium";v="131", "Not=A?Brand";v="24"'
    ),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
    "sec-ch-ua-full-version-list": (
        '"Microsoft Edge";v="131.0.2903.112", '
        '"Chromium";v="131.0.6778.205", '
        '"Not=A?Brand";v="24.0.0.0"'
    ),
}

_OPERA_CH = {
    "sec-ch-ua": (
        '"Opera";v="115", "Chromium";v="130", "Not=A?Brand";v="24"'
    ),
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-platform-version": '"10.0.0"',
    "sec-ch-ua-arch": '"x86"',
    "sec-ch-ua-bitness": '"64"',
}

CLIENT_HINTS_BY_BROWSER: dict[BrowserFamily, dict[str, str]] = {
    BrowserFamily.CHROME: _CHROME_CLIENT_HINTS,
    BrowserFamily.FIREFOX: {},
    BrowserFamily.SAFARI: {},
    BrowserFamily.EDGE: _EDGE_CH,
    BrowserFamily.OPERA: _OPERA_CH,
}

CLIENT_HINTS_BY_UA: dict[str, dict[str, str]] = {
    _CHROME_131_WIN: _CHROME_CLIENT_HINTS,
    _CHROME_131_MAC: _CHROME_MAC_CH,
    _CHROME_131_LINUX: _CHROME_LINUX_CH,
    _CHROME_131_ANDROID: _CHROME_ANDROID_CH,
    _CHROME_131_CR_OS: {
        **_CHROME_CLIENT_HINTS, "sec-ch-ua-platform": '"Chrome OS"',
    },
    _CHROME_130_WIN: {
        **_CHROME_CLIENT_HINTS,
        "sec-ch-ua": (
            '"Google Chrome";v="130", "Chromium";v="130", "Not=A?Brand";v="99"'
        ),
    },
    _CHROME_129_WIN: {
        **_CHROME_CLIENT_HINTS,
        "sec-ch-ua": (
            '"Google Chrome";v="129", "Chromium";v="129", "Not=A?Brand";v="99"'
        ),
    },
    _EDGE_131_WIN: _EDGE_CH,
    _EDGE_131_MAC: {**_EDGE_CH, "sec-ch-ua-platform": '"macOS"'},
    _OPERA_115_WIN: _OPERA_CH,
}

# ── curl_cffi impersonation targets ────────────────────────────────────

CURL_CFFI_TARGETS: dict[BrowserFamily, str] = {
    BrowserFamily.CHROME: "chrome131",
    BrowserFamily.FIREFOX: "firefox133",
    BrowserFamily.SAFARI: "safari18_2",
    BrowserFamily.EDGE: "edge101",
    BrowserFamily.OPERA: "chrome131",
}

UA_TO_CURL_TARGET: dict[str, str] = {}
for _ua in CHROME_UAS:
    UA_TO_CURL_TARGET[_ua] = "chrome131"
for _ua in CHROME_UAS:
    if "Android" in _ua:
        UA_TO_CURL_TARGET[_ua] = "chrome131_android"
for _ua in FIREFOX_UAS:
    UA_TO_CURL_TARGET[_ua] = "firefox133"
for _ua in SAFARI_UAS:
    UA_TO_CURL_TARGET[_ua] = "safari18_2"
for _ua in EDGE_UAS:
    UA_TO_CURL_TARGET[_ua] = "edge101"
for _ua in OPERA_UAS:
    UA_TO_CURL_TARGET[_ua] = "chrome131"


# ── Accept-* headers ───────────────────────────────────────────────────

ACCEPT_LANG_POOL: tuple[str, ...] = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "ar-SA,ar;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
)

ACCEPT_ENC_POOL: tuple[str, ...] = (
    "gzip, deflate, br",
    "gzip, deflate",
    "br, gzip, deflate",
)

_CHROME_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,image/apng,*/*;q=0.8"
)
_FIREFOX_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8"
)
_SAFARI_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
)
_LOW_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

ACCEPT_BY_FAMILY: dict[BrowserFamily, str] = {
    BrowserFamily.CHROME: _CHROME_ACCEPT,
    BrowserFamily.FIREFOX: _FIREFOX_ACCEPT,
    BrowserFamily.SAFARI: _SAFARI_ACCEPT,
    BrowserFamily.EDGE: _CHROME_ACCEPT,
    BrowserFamily.OPERA: _CHROME_ACCEPT,
}

REFERRER_POOL: tuple[str | None, ...] = (
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    None,
)

# ── Viewport / screen dimensions (for Sec-CH-Viewport-* if needed) ─────

VIEWPORTS: dict[Platform, tuple[int, int]] = {
    Platform.WINDOWS: (1920, 1080),
    Platform.MACOS: (1728, 1117),
    Platform.LINUX: (1920, 1080),
    Platform.ANDROID: (412, 915),
    Platform.IOS: (393, 852),
    Platform.CHROMEOS: (1366, 768),
}

# ── Profile dataclass ──────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentityProfile:
    family: BrowserFamily
    user_agent: str
    platform: Platform
    accept: str
    accept_language: str
    accept_encoding: str
    dnt: str = "1"
    upgrade_insecure_requests: str = "1"
    sec_fetch_dest: str = "document"
    sec_fetch_mode: str = "navigate"
    sec_fetch_site: str = "none"
    sec_fetch_user: str = "?1"
    client_hints: dict[str, str] = field(default_factory=dict)
    curl_target: str = ""
    referer: str | None = None
    viewport: tuple[int, int] = (1920, 1080)

    def all_headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept": self.accept,
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
            "Upgrade-Insecure-Requests": self.upgrade_insecure_requests,
            "Sec-Fetch-Dest": self.sec_fetch_dest,
            "Sec-Fetch-Mode": self.sec_fetch_mode,
            "Sec-Fetch-Site": self.sec_fetch_site,
            "Sec-Fetch-User": self.sec_fetch_user,
        }
        if self.dnt != "0":
            h["DNT"] = self.dnt
        if self.referer:
            h["Referer"] = self.referer
        for k, v in self.client_hints.items():
            h[k] = v
        return h


# ── Build functions ────────────────────────────────────────────────────

def detect_platform(ua: str) -> Platform:
    if "Windows" in ua:
        return Platform.WINDOWS
    if "Macintosh" in ua:
        return Platform.MACOS
    if "Android" in ua:
        return Platform.ANDROID
    if "iPhone" in ua or "iPad" in ua:
        return Platform.IOS
    if "CrOS" in ua:
        return Platform.CHROMEOS
    return Platform.LINUX


def random_ua(family: BrowserFamily = BrowserFamily.CHROME) -> str:
    return random.choice(UA_POOL.get(family, CHROME_UAS))


def random_accept_language() -> str:
    return random.choice(ACCEPT_LANG_POOL)


def random_accept_encoding() -> str:
    return random.choice(ACCEPT_ENC_POOL)


def random_dnt() -> str:
    return random.choice(("0", "1"))


def random_referer() -> str | None:
    return random.choice(REFERRER_POOL)


def random_fetch_site() -> str:
    return random.choice(("none", "same-origin", "cross-site"))


def build_identity_profile(
    family: BrowserFamily = BrowserFamily.CHROME,
) -> IdentityProfile:
    ua = random_ua(family)
    platform = detect_platform(ua)
    ch = CLIENT_HINTS_BY_UA.get(ua, CLIENT_HINTS_BY_BROWSER.get(family, {}))
    return IdentityProfile(
        family=family,
        user_agent=ua,
        platform=platform,
        accept=ACCEPT_BY_FAMILY.get(family, _CHROME_ACCEPT),
        accept_language=random_accept_language(),
        accept_encoding=random_accept_encoding(),
        dnt=random_dnt(),
        sec_fetch_site=random_fetch_site(),
        client_hints=dict(ch),
        curl_target=UA_TO_CURL_TARGET.get(ua, "chrome131"),
        referer=random_referer(),
        viewport=VIEWPORTS.get(platform, (1920, 1080)),
    )


def build_low_profile_headers() -> dict[str, str]:
    return {
        "User-Agent": random_ua(),
        "Accept": _LOW_ACCEPT,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }


def validate_identity_consistency(profile: IdentityProfile) -> bool:
    ua = profile.user_agent
    ch = profile.client_hints
    if not ch:
        return True
    ch_platform = ch.get("sec-ch-ua-platform", "").strip('"')
    if "Windows" in ch_platform:
        return "Windows" in ua
    if "macOS" in ch_platform:
        return "Macintosh" in ua
    if "Linux" in ch_platform:
        return "Linux" in ua and "Android" not in ua
    if "Android" in ch_platform:
        return "Android" in ua
    if "Chrome OS" in ch_platform:
        return "CrOS" in ua
    return True
