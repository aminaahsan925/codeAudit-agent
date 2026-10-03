"""Link extraction for the bounded website crawler.

Stdlib only (html.parser): collects ``<a href>`` targets, resolves them
against the page URL, strips fragments, and keeps only http(s) links.
No JavaScript execution, no form submission — the crawler sees what a
plain GET returns.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.hrefs.append(value)


def extract_links(html: str, base_url: str) -> list[str]:
    """Extract absolute http(s) links from an HTML page.

    Never raises on malformed markup: unparseable input yields no links
    rather than failing the crawl.
    """
    links: list[str] = []
    try:
        parser = _LinkExtractor()
        parser.feed(html)
        raw_hrefs = parser.hrefs
    except Exception:
        return []
    for href in raw_hrefs:
        href = href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        try:
            absolute = urljoin(base_url, href)
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if (parts.scheme or "").lower() not in ("http", "https"):
            continue
        if not parts.hostname:
            continue
        # Strip the fragment: it never changes the fetched resource.
        links.append(urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")))
    # Stable, deduplicated order.
    return list(dict.fromkeys(links))
