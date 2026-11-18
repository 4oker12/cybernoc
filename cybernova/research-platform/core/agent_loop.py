"""Bounded local Qwen tool-calling loop for Cybernova.

No shell access. No remote network targets. Only offline_tools.SPECS read-only
research actions are exposed to the model. Writable finding review is reserved
for the human/UI workflow. Tool receipts are generated only after real calls.
"""
from __future__ import annotations
import http.client
import json
from pathlib import Path
import re

from core.offline_tools import SPECS, ToolError, dispatch_tool

PROMPT_FILE=Path(__file__).resolve().parents[1]/"prompts/RESEARCHER_SYSTEM.md"
MAX_TURNS=5
MAX_TOOLS=8
MODEL_TOOLS=frozenset(SPECS)-{"finding_create","finding_verify","audit_event_log"}
SELECT_OPTIONS={
    "scheme":["http","https"],"impact":["low","medium","high"],
    "likelihood":["low","medium","high"],"confidence":["low","medium","high"],
    "state":["observation","hypothesis","verified","rejected"],
}
MODEL_ID_RE=re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")

def tool_schemas():
    result=[]
    for name in sorted(MODEL_TOOLS):
        config=SPECS[name]
        props={}
        required=[]
        for fld in config["fields"]:
            p={"type":"string","description":fld.get("label",fld["name"])}
            if fld["name"] in SELECT_OPTIONS:
                p["enum"]=SELECT_OPTIONS[fld["name"]]
            if fld["name"] in ("schema","steps"):
                p["description"]+=" (JSON encoded as a text string)"
            props[fld["name"]]=p
            if fld.get("required"):
                required.append(fld["name"])
        result.append({"type":"function","function":{"name":name,
            "description":config["description"],
            "parameters":{"type":"object","properties":props,
                          "required":required,"additionalProperties":False}}})
    return result


class OllamaClient:
    """Connects *only* to local Ollama on fixed loopback port 11434."""
    def __init__(self, model="cybernova-security:30b", timeout=180):
        if not MODEL_ID_RE.fullmatch(model):
            raise ValueError("Invalid Ollama model ID")
        self.model=model
        self.timeout=timeout

    def complete(self, messages, tools):
        body=json.dumps({
            "model":self.model,"messages":messages,"tools":tools,
            "stream":False,"options":{"temperature":0.2,"num_predict":1400}
        },ensure_ascii=False).encode("utf-8")
        if len(body)>240000:
            raise ValueError("Model request exceeds safe size")
        con=http.client.HTTPConnection("127.0.0.1",11434,timeout=self.timeout)
        try:
            con.request("POST","/api/chat",body=body,
                headers={"Content-Type":"application/json",
                         "Content-Length":str(len(body))})
            res=con.getresponse()
            response=res.read(160000)
            if res.status!=200:
                raise RuntimeError(f"Local Ollama HTTP {res.status}")
            data=json.loads(response)
            if not isinstance(data,dict) or not isinstance(data.get("message"),dict):
                raise RuntimeError("Invalid Ollama chat response")
            return data["message"]
        finally:
            con.close()


def run_research(question:str, client, context:dict, max_turns=MAX_TURNS):
    if not isinstance(question,str) or not 5<=len(question)<=3000:
        raise ValueError("Research question length invalid")
    if not 1<=max_turns<=MAX_TURNS:
        raise ValueError("Invalid turn budget")
    system=PROMPT_FILE.read_text(encoding="utf-8")
    messages=[{"role":"system","content":system},
              {"role":"user","content":question}]
    schemas=tool_schemas()
    receipts=[]
    for index in range(max_turns):
        response=client.complete(messages,schemas)
        if not isinstance(response,dict):
            return {"ok":False,"state":"invalid_model_reply","receipts":receipts}
        calls=response.get("tool_calls") or []
        content=response.get("content") or ""
        if not isinstance(content,str):
            content=""
        if not isinstance(calls,list) or len(calls)>MAX_TOOLS:
            return {"ok":False,"state":"invalid_model_tool_calls","receipts":receipts}
        if not calls:
            lower=content.lower()
            if "<tool_call>" in lower or '"function":{"name":' in lower:
                return {"ok":False,"state":"text_imitation_of_tool_call",
                        "answer":"Модель напечатала имитацию вызова инструмента. Реального вызова не произошло.",
                        "receipts":receipts,"model_turns":index+1}
            return {"ok":True,"state":"answered","answer":content[:15000],
                    "receipts":receipts,"model_turns":index+1,
                    "verified_tool_calls":sum(x.get("executed",False) for x in receipts)}
        # Insert actual assistant function call message before response tool messages.
        messages.append({"role":"assistant","content":content[:4000],"tool_calls":calls})
        for call in calls:
            if len(receipts)>=MAX_TOOLS:
                return {"ok":False,"state":"tool_budget_exhausted","receipts":receipts}
            function=call.get("function",{}) if isinstance(call,dict) else {}
            name=function.get("name","") if isinstance(function,dict) else ""
            args=function.get("arguments",{}) if isinstance(function,dict) else {}
            if isinstance(args,str):
                try:
                    args=json.loads(args) if len(args)<20000 else None
                except json.JSONDecodeError:
                    args=None
            receipt={"tool":str(name)[:120],"executed":False,"ok":False}
            if name not in MODEL_TOOLS:
                receipt["error"]="tool_not_exposed_to_model"
            elif not isinstance(args,dict) or len(json.dumps(args))>20000:
                receipt["error"]="invalid_tool_arguments"
            else:
                try:
                    result=dispatch_tool(name,args,context)
                    receipt.update({"executed":True,"ok":True,
                                    "result":result.get("result")})
                except (ValueError,ToolError,TypeError) as exc:
                    receipt["error"]=str(exc)[:180]
            receipts.append(receipt)
            tool_result=json.dumps(receipt,ensure_ascii=False)
            if len(tool_result)>16000:
                tool_result=json.dumps({"tool":receipt["tool"],"ok":receipt["ok"],
                  "error":"result_too_large_for_model"},ensure_ascii=False)
            messages.append({"role":"tool","name":receipt["tool"],
                             "content":tool_result})
    return {"ok":False,"state":"model_turn_budget_exhausted",
            "answer":"Цикл достиг лимита без окончательного ответа. Продолжение не запускалось.",
            "receipts":receipts,"model_turns":max_turns,
            "verified_tool_calls":sum(x.get("executed",False) for x in receipts)}
