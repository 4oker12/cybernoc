"""Regression for the editorial renderer and sanitized DeepSeek output."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]
MARKDOWN=ROOT/"console"/"static"/"markdown.js"


@unittest.skipUnless(shutil.which("node"), "Node.js is required")
class EditorialMarkdownTests(unittest.TestCase):
    def test_headings_are_semantic_and_tool_markup_is_hidden(self):
        script=r"""
const assert=require("node:assert/strict");
const fs=require("node:fs");
const vm=require("node:vm");
class Node {
  constructor(tag) {
    this.tag=tag;this.children=[];this.className="";this.textContent="";
    this.dataset={};this.href="";this.rel="";this.target="";
  }
  append(...nodes){this.children.push(...nodes);}
  appendChild(node){this.children.push(node);return node;}
}
const document={
  createElement:(tag)=>new Node(tag),
  createTextNode:(text)=>({tag:"#text",textContent:String(text)})
};
const window={};
vm.runInNewContext(fs.readFileSync(process.argv[1],"utf8"),{document,window,URL});
const {render,normalizeAssistantText}=window.CybernovaMarkdown;
const root=render("## Вывод\n\n**Подтверждено:** 3 успешных проверки.\n\n## Повторная проверка\n\nОшибок не обнаружено.");
assert.equal(root.children[0].tag,"h2");
assert.equal(root.children[2].tag,"h2");
assert.equal(root.children[0].children[0].textContent,"Вывод");
assert.equal(render("Вывод: результат").children[0].tag,"h2");
assert.equal(render("Повторная проверка: расхождений нет").children[0].tag,"h2");
assert.equal(render("Ограничения: отсутствуют").children[0].tag,"h2");
const leaked='< | | DSML | | calls>< | | DSML | | invoke name="dev_read">< | | DSML | | parameter name="path">a.py</ | | DSML | | parameter></ | | DSML | | invoke></ | | DSML | | calls>';
assert(!normalizeAssistantText(leaked).includes("dev_read"));
assert(!normalizeAssistantText("Примечание. "+leaked).includes("dev_read"));
const escaped='&lt;&#124;DSML&#124;invoke name=&quot;dev_read&quot;&gt;...';
assert(!normalizeAssistantText(escaped).includes("dev_read"));
const fullwidth='＜｜DSML｜invoke name="dev_read">...';
assert(!normalizeAssistantText(fullwidth).includes("dev_read"));
const tick=String.fromCharCode(96).repeat(3);
const fenced=tick+"text\n<｜DSML｜invoke name=\"dev_read\">sample\n"+tick;
assert.equal(normalizeAssistantText(fenced),fenced);
assert.equal(render(fenced).children[0].tag,"pre");
assert.equal(normalizeAssistantText("Проверяем формат DSML без тегов"),"Проверяем формат DSML без тегов");
assert.equal(render("Обычный текст <div> без интерпретации HTML").children[0].tag,"p");
console.log("editorial_markdown_and_dsml PASS");
"""
        outcome=subprocess.run(
            ["node","-e",script,str(MARKDOWN)],capture_output=True,text=True,
            timeout=15,check=False
        )
        self.assertEqual(outcome.returncode,0,outcome.stdout+"\n"+outcome.stderr)
        self.assertIn("editorial_markdown_and_dsml PASS",outcome.stdout)


if __name__=="__main__":
    unittest.main()
