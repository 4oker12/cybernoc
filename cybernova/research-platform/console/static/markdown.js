"use strict";
/* Small, dependency-free Markdown renderer for untrusted LLM answers.
 * DOM nodes and textContent ONLY: no innerHTML, eval, scripts, raw HTML,
 * inline event attributes or user-controlled URL schemes.
 */
(function () {
  const el=(tag,cls)=>{const n=document.createElement(tag);if(cls)n.className=cls;return n;};
  const blockRE=/^\s*(?:#{1,5}\s|[-*+]\s|\d+[.)]\s|>\s?|\x60{3}|~{3}|\|)/;
  function inline(parent,text){
    const tokens=String(text).split(/(\x60[^\x60\n]+\x60|\*\*[^*\n]+\*\*|~~[^~\n]+~~|\*[^*\n]+\*|\[[^\]\n]+\]\([^) \n]+\))/g);
    for(const token of tokens){
      if(!token)continue;
      let n=null,value=token;
      if(token.startsWith("\x60")&&token.endsWith("\x60")){n=el("code");value=token.slice(1,-1);}
      else if(token.startsWith("**")&&token.endsWith("**")){n=el("strong");value=token.slice(2,-2);}
      else if(token.startsWith("~~")&&token.endsWith("~~")){n=el("del");value=token.slice(2,-2);}
      else if(token.startsWith("*")&&token.endsWith("*")){n=el("em");value=token.slice(1,-1);}
      else if(token[0]==="["){
        const m=/^\[([^\]\n]+)\]\(([^) \n]+)\)$/.exec(token);
        if(m){
          try{
            const url=new URL(m[2]);
            if(["https:","http:"].includes(url.protocol)&&!url.username&&!url.password){
              n=el("a");n.href=url.href;n.target="_blank";n.rel="noopener noreferrer";
              value=m[1];
            }
          }catch(_){}
        }
      }
      if(n){n.textContent=value;parent.append(n);}
      else parent.append(document.createTextNode(token));
    }
    return parent;
  }
  function cells(line){
    const t=line.trim();
    if(!t.includes("|")||!(t.startsWith("|")||t.endsWith("|")))return null;
    const result=t.replace(/^\|/,"").replace(/\|$/,"").split("|").map(x=>x.trim());
    return result.some(Boolean)?result:null;
  }
  function divider(c){
    return c&&c.length>0&&c.every(x=>/^:?-{3,}:?$/.test(x));
  }
  function section(line){
    const m=/^\s*(?:\*\*)?(Рекомендаци[яи](?:\s+по\s+приоритету|\s+Qwen)?|Что\s+проверено|Повторная\s+проверка|Ограничения|Следующ(?:ий|ие)\s+шаг(?:и)?|Критери[йи]\s+успеха|Итог|Вывод|Факты|Гипотезы|Риски|Что проверить)(?:\*\*)?\s*[:—–-]?\s*(.*)$/i.exec(line);
    if(!m)return null;
    const kind=/рекомендац/i.test(m[1])?"recommendation":
      /риски|ограничения/i.test(m[1])?"risk":
      /гипотез/i.test(m[1])?"hypothesis":
      /шаг|провер/i.test(m[1])?"steps":
      /критери/i.test(m[1])?"criteria":"finding";
    return {title:m[1],detail:m[2]||"",kind};
  }
  function normalizeAssistantText(value){
    const text=String(value??"");
    if(/^\s*(?:`{3,}|~{3,})/.test(text))return text; // A literal code example.
    if(!/DSML/i.test(text))return text;
    const canonical=text
      .replace(/&lt;|&#0*60;|&#x0*3c;/gi,"<")
      .replace(/&gt;|&#0*62;|&#x0*3e;/gi,">")
      .replace(/&#0*124;|&#x0*7c;/gi,"|")
      .replace(/[＜‹]/g,"<").replace(/[＞›]/g,">");
    const marker=/<\s*\/?\s*(?:[|｜]\s*){1,2}DSML\b/i.test(canonical);
    const hasProtocol=/\b(?:invoke\s+name\s*=|(?:function_)?calls\s*>|parameter\s+name\s*=)/i.test(canonical);
    if(!marker||!hasProtocol)return text;
    return "Служебный протокол вызова инструмента скрыт. "+
      "Этот технический ответ не является итогом задачи; "+
      "результаты выполненных вызовов доступны в разделе «Инструменты».";
  }
  function render(value){
    const root=el("div","md-content");
    const lines=normalizeAssistantText(value).replace(/\r\n?/g,"\n").split("\n");
    let i=0,blocks=0;
    while(i<lines.length && blocks<2000){
      blocks++;
      const raw=lines[i], trimmed=raw.trim();
      if(!trimmed){i++;continue;}
      const fence=/^\s*(\x60{3,}|~{3,})([A-Za-z0-9_.+-]*)/.exec(raw);
      if(fence){
        const lang=fence[2], marker=fence[1][0], count=fence[1].length;
        i++;
        const rows=[];
        while(i<lines.length && !new RegExp("^\\s*"+(marker==="\x60"?"\x60":"~")+"{"+count+",}\\s*$").test(lines[i])){
          rows.push(lines[i]);i++;
        }
        if(i<lines.length)i++;
        const pre=el("pre","md-code"),code=el("code");
        if(lang)code.dataset.language=lang.slice(0,30);
        code.textContent=rows.join("\n");pre.append(code);root.append(pre);continue;
      }
      const heading=/^\s*(#{1,5})\s+(.+)$/.exec(raw);
      if(heading){
        const semantic=section(heading[2].trim());
        const classes=semantic?"md-section md-section--"+semantic.kind:"";
        const h=el("h"+Math.max(2,Math.min(heading[1].length,5)),classes);
        if(semantic)h.dataset.sectionKind=semantic.kind;
        inline(h,heading[2]);root.append(h);i++;continue;
      }
      if(/^([-*_])\1{2,}\s*$/.test(trimmed)){root.append(el("hr"));i++;continue;}
      const note=section(trimmed);
      if(note && !(trimmed.includes("|")&&i+1<lines.length&&divider(cells(lines[i+1]))) &&
         (trimmed.startsWith("**")||note.detail.length<160)){
        const h=el("h2","md-section md-section--"+note.kind);
        h.dataset.sectionKind=note.kind;
        inline(h,note.title);root.append(h);
        if(note.detail){inline(root.appendChild(el("p")),note.detail.replace(/^\*+/,""));}
        i++;continue;
      }
      const first=cells(raw);
      if(first){
        const rows=[];
        while(i<lines.length){const c=cells(lines[i]);if(!c||c.length!==first.length)break;rows.push(c);i++;}
        if(first.length>=2 && rows.length>=2){
          const wrap=el("div","md-table-wrap"),table=el("table","md-table");
          let idx=0;
          if(!divider(rows[0])){
            const thead=el("thead"),tr=el("tr");
            for(const c of rows[0])inline(tr.appendChild(el("th")),c);
            thead.append(tr);table.append(thead);idx=1;
          }
          if(rows[idx]&&divider(rows[idx]))idx++;
          const tbody=el("tbody");
          for(const row of rows.slice(idx)){
            if(divider(row))continue;
            const tr=el("tr");
            for(const c of row)inline(tr.appendChild(el("td")),c);
            tbody.append(tr);
          }
          table.append(tbody);wrap.append(table);root.append(wrap);
        }else{
          const ul=el("ul","md-pipe-list");
          for(const row of rows){const li=el("li");inline(li,row.join(" · "));ul.append(li);}
          root.append(ul);
        }
        continue;
      }
      const bullet=/^\s*([-*+]|\d+[.)])\s+(.+)$/.exec(raw);
      if(bullet){
        const numbered=/^\d/.test(bullet[1]),list=el(numbered?"ol":"ul");
        while(i<lines.length){
          const m=/^\s*([-*+]|\d+[.)])\s+(.+)$/.exec(lines[i]);
          if(!m||numbered!==/^\d/.test(m[1]))break;
          inline(list.appendChild(el("li")),m[2]);i++;
        }
        root.append(list);continue;
      }
      if(/^\s*>\s?/.test(raw)){
        const q=el("blockquote");
        while(i<lines.length&&/^\s*>\s?/.test(lines[i])){inline(q.appendChild(el("p")),lines[i].replace(/^\s*>\s?/,""));i++;}
        root.append(q);continue;
      }
      const paragraph=[trimmed];i++;
      while(i<lines.length && lines[i].trim() && !blockRE.test(lines[i]) &&
            !section(lines[i].trim())){
        paragraph.push(lines[i].trim());i++;
      }
      inline(root.appendChild(el("p")),paragraph.join(" "));
    }
    return root;
  }
  window.CybernovaMarkdown={render,normalizeAssistantText};
})();