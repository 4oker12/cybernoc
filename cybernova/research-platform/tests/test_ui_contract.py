"""Static UI contract checks: all JS-linked element IDs exist and no unsafe DOM injection."""
import re
import unittest
from pathlib import Path
from html.parser import HTMLParser

ROOT=Path(__file__).resolve().parents[1]

class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids=[]
        self.views=[]
        self.nav=[]
        self.remote_assets=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if a.get("id"):
            self.ids.append(a["id"])
        if a.get("id","").startswith("view-"):
            self.views.append(a["id"].removeprefix("view-"))
        if a.get("data-nav"):
            self.nav.append(a["data-nav"])
        if tag in ("script","link"):
            src=a.get("src",a.get("href",""))
            if src.startswith(("http:","https:","//")):
                self.remote_assets.append(src)

class UIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html=(ROOT/"ui/index.html").read_text(encoding="utf-8")
        cls.js=(ROOT/"ui/app.js").read_text(encoding="utf-8")
        cls.css=(ROOT/"ui/style.css").read_text(encoding="utf-8")
        cls.doc=Collector()
        cls.doc.feed(cls.html)

    def test_js_selectors_have_html_element(self):
        ids=set(re.findall(r'\$\("#([a-zA-Z0-9_-]+)"\)',self.js))
        missing=ids-set(self.doc.ids)
        self.assertEqual(missing,set(),f"Missing HTML element IDs: {missing}")

    def test_unique_ids_and_valid_routes(self):
        self.assertEqual(len(self.doc.ids),len(set(self.doc.ids)))
        self.assertEqual(set(self.doc.nav),set(self.doc.views))
        self.assertEqual(set(self.doc.views),
              {"overview","agent","tools","cases","report"})

    def test_no_remote_ui_assets_or_innerhtml(self):
        self.assertEqual(self.doc.remote_assets,[])
        self.assertNotIn("innerHTML",self.js)
        self.assertIn("textContent",self.js)

    def test_csrf_marker_and_accessible_inputs(self):
        self.assertIn('__CSRF_TOKEN__',self.html)
        self.assertIn('name="cybernova-csrf"',self.html)
        self.assertIn('aria-live="polite"',self.html)
        self.assertIn('max-width:620px',self.css)


if __name__=="__main__":
    unittest.main()
