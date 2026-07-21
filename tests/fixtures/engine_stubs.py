"""Minimal nova3-like engine stub used by install/audit tests."""

CLEAN_ENGINE_SOURCE = """\
#VERSION: 1.0
#AUTHORS: Test
from novaprinter import prettyPrinter


class demo:
    url = "https://example.com"
    name = "Demo"
    supported_categories = {"all": ""}

    def search(self, what, cat="all"):
        prettyPrinter(
            {
                "link": "magnet:?xt=urn:btih:0",
                "name": what,
                "size": "1 B",
                "seeds": 1,
                "leech": 0,
                "engine_url": self.url,
                "desc_link": self.url,
            }
        )
"""

CLEAN_ENGINE_BYTES = CLEAN_ENGINE_SOURCE.encode("utf-8")


def engine_source(
    *,
    stem: str = "demo",
    extra_imports: str = "",
    body: str = "",
    class_name: str | None = None,
) -> str:
    """Build a small engine module; *body* is inserted inside search()."""
    cls = class_name or stem
    search_body = body or (
        "prettyPrinter({'link': 'magnet:?xt=urn:btih:0', 'name': what, "
        "'size': '1 B', 'seeds': 1, 'leech': 0, 'engine_url': self.url, "
        "'desc_link': self.url})"
    )
    return (
        f"#VERSION: 1.0\n"
        f"from novaprinter import prettyPrinter\n"
        f"{extra_imports}"
        f"class {cls}:\n"
        f'    url = "https://example.com"\n'
        f'    name = "Demo"\n'
        f'    supported_categories = {{"all": ""}}\n'
        f"    def search(self, what, cat='all'):\n"
        f"        {search_body}\n"
    )
