"""Header Canon — Complete browser-canonical HTTP header ordering.

Phase: HUMAN-MIMICRY-B — Extended ordering with sec-ch-ua* Client Hints
headers in their correct positions for Chrome, Firefox, Safari, Edge.

Header ordering matters for TLS fingerprinting (JA4H) and WAF bypass.
Real browsers send headers in a consistent, predictable order.
"""

from __future__ import annotations


CHROME_HEADER_ORDER: tuple[str, ...] = (
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "sec-ch-ua-full-version-list",
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "accept-encoding",
    "accept-language",
    "cookie",
    "dnt",
    "referer",
)

FIREFOX_HEADER_ORDER: tuple[str, ...] = (
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "dnt",
    "cookie",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "referer",
)

SAFARI_HEADER_ORDER: tuple[str, ...] = (
    "upgrade-insecure-requests",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "dnt",
    "cookie",
    "referer",
)

EDGE_HEADER_ORDER: tuple[str, ...] = CHROME_HEADER_ORDER

OPERA_HEADER_ORDER: tuple[str, ...] = CHROME_HEADER_ORDER

HEADER_ORDER_BY_BROWSER: dict[str, tuple[str, ...]] = {
    "chrome": CHROME_HEADER_ORDER,
    "firefox": FIREFOX_HEADER_ORDER,
    "safari": SAFARI_HEADER_ORDER,
    "edge": EDGE_HEADER_ORDER,
    "opera": OPERA_HEADER_ORDER,
}


def order_headers(
    headers: dict[str, str], browser: str = "chrome"
) -> list[tuple[str, str]]:
    canon = HEADER_ORDER_BY_BROWSER.get(browser, CHROME_HEADER_ORDER)
    header_lower = {k.lower(): k for k in headers}
    ordered: list[tuple[str, str]] = []
    seen: set[str] = set()
    for hdr in canon:
        original = header_lower.get(hdr)
        if original is not None and original not in seen:
            ordered.append((original, headers[original]))
            seen.add(original)
    for k, v in headers.items():
        if k not in seen:
            ordered.append((k, v))
            seen.add(k)
    return ordered
