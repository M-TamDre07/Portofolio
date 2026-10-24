"""Regression tests for the shared public website experience.

These checks keep the core pages consistent and catch common accessibility and
responsive-layout regressions without depending on an external browser service.
"""
from __future__ import annotations

import json
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
CORE_PAGES = (
    "index.html",
    "software/index.html",
    "software/paketscope.html",
    "software/prompter-overlay.html",
)


class PageAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_lang = ""
        self.meta: dict[str, str] = {}
        self.canonicals: list[str] = []
        self.stylesheets: list[str] = []
        self.ids: list[str] = []
        self.h1_count = 0
        self.skip_links: list[str] = []
        self.inline_scripts = 0
        self.inline_styles = 0
        self.inline_event_handlers: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html":
            self.html_lang = values.get("lang", "") or ""
        if tag == "meta":
            name = values.get("name", "")
            if name:
                self.meta[name.lower()] = values.get("content", "") or ""
        if tag == "link":
            rel = (values.get("rel", "") or "").lower().split()
            href = values.get("href", "") or ""
            if "canonical" in rel:
                self.canonicals.append(href)
            if "stylesheet" in rel:
                self.stylesheets.append(href)
        if "id" in values:
            self.ids.append(values["id"] or "")
        if tag == "h1":
            self.h1_count += 1
        if tag == "a" and "skip-link" in (values.get("class", "") or "").split():
            self.skip_links.append(values.get("href", "") or "")
        if tag == "script" and not values.get("src"):
            script_type = (values.get("type") or "").split(";", 1)[0].strip().casefold()
            # application/ld+json is a non-executable data block, not inline JavaScript.
            if script_type != "application/ld+json":
                self.inline_scripts += 1
        if "style" in values:
            self.inline_styles += 1
        self.inline_event_handlers.extend(
            name for name in values if re.fullmatch(r"on[a-z]+", name.lower())
        )


class WebsiteExperienceTests(unittest.TestCase):
    def parse_page(self, relative: str) -> tuple[str, PageAudit]:
        path = PUBLIC / relative
        self.assertTrue(path.is_file(), f"Missing page: {relative}")
        source = path.read_text(encoding="utf-8")
        parser = PageAudit()
        parser.feed(source)
        parser.close()
        return source, parser

    def test_all_primary_pages_share_responsive_and_accessible_basics(self) -> None:
        for relative in CORE_PAGES:
            with self.subTest(page=relative):
                source, page = self.parse_page(relative)
                self.assertEqual(page.html_lang, "id")
                self.assertIn("width=device-width", page.meta.get("viewport", ""))
                self.assertTrue(page.meta.get("description", "").strip())
                self.assertEqual(len(page.canonicals), 1)
                self.assertTrue(page.canonicals[0].startswith("https://"))
                self.assertEqual(page.h1_count, 1)
                self.assertIn("/assets/css/experience.css", page.stylesheets)
                self.assertIn("main", page.ids)
                self.assertIn("#main", page.skip_links)
                self.assertEqual(page.inline_scripts, 0, "Scripts must be external to satisfy CSP.")
                self.assertEqual(page.inline_styles, 0, "Use the shared stylesheet instead of style attributes.")
                self.assertEqual(page.inline_event_handlers, [])
                self.assertIn('id="themeToggle"', source)
                self.assertIn('id="menuToggle"', source)

    def test_shared_stylesheet_contains_mobile_and_accessibility_rules(self) -> None:
        css = (PUBLIC / "assets" / "css" / "experience.css").read_text(encoding="utf-8")
        self.assertRegex(css, r"@media\s*\(max-width:\s*780px\)")
        self.assertRegex(css, r"@media\s*\(max-width:\s*700px\)")
        self.assertRegex(css, r"@media\s*\(max-width:\s*380px\)")
        self.assertIn("prefers-reduced-motion:reduce", css)
        self.assertIn(":focus-visible", css)
        self.assertIn("minmax(0,1fr)", css)

    def test_catalogue_has_operable_search_and_filters(self) -> None:
        source, _ = self.parse_page("software/index.html")
        for identifier in (
            "softwareSearch", "statusFilters", "categoryFilter",
            "platformFilter", "sortFilter", "clearFilters", "loadMore",
        ):
            with self.subTest(control=identifier):
                self.assertIn(f'id="{identifier}"', source)
        self.assertIn('aria-live="polite"', source)
        self.assertIn('aria-pressed="true"', source)

    def test_paketscope_page_is_explicit_about_installation_state(self) -> None:
        source, _ = self.parse_page("software/paketscope.html")
        self.assertIn('id="install-status"', source)
        self.assertIn("Belum tersedia untuk instalasi publik", source)
        manifest = (ROOT / "apps" / "paketscope" / "pyproject.toml").read_text(encoding="utf-8")
        app_version = next(line for line in manifest.splitlines() if line.startswith("version = ")).split('"')[1]
        self.assertIn(app_version, source)
        self.assertNotIn("apt install paketscope", source.lower())
        self.assertNotIn("curl | sudo", source.lower())


    def test_home_canonical_uses_verified_production_domain(self) -> None:
        _, home = self.parse_page("index.html")
        expected = "https://linux-software-lab.vercel.app/"
        self.assertEqual(home.canonicals, [expected])
        sitemap = (PUBLIC / "sitemap.xml").read_text(encoding="utf-8")
        robots = (PUBLIC / "robots.txt").read_text(encoding="utf-8")
        self.assertIn(expected, sitemap)
        self.assertIn("Sitemap: https://linux-software-lab.vercel.app/sitemap.xml", robots)
        self.assertNotIn("muhammadandrea.vercel.app", sitemap + robots)

    def test_catalogue_and_product_page_agree_on_paketscope_version(self) -> None:
        data = json.loads((PUBLIC / "data" / "software.json").read_text(encoding="utf-8"))
        app = next(row for row in data["software"] if row["id"] == "paketscope")
        page, _ = self.parse_page("software/paketscope.html")
        manifest = (ROOT / "apps" / "paketscope" / "pyproject.toml").read_text(encoding="utf-8")
        app_version = next(line for line in manifest.splitlines() if line.startswith("version = ")).split('"')[1]
        self.assertEqual(app["version"], app_version)
        self.assertIn(app_version, page)
        self.assertIn("PaketScope 3", page)
        self.assertEqual(app["status"], "testing")
        self.assertEqual(app["releaseUrl"], "")


if __name__ == "__main__":
    unittest.main()
