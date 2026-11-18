"""Fixed-profile well-known scanners, exclusively for explicitly configured labs.

Supports Nmap, Nuclei, OWASP ZAP Baseline, Nikto, testssl.sh, ffuf,
Semgrep and Trivy. The model supplies ONLY a lab target ID or project ID,
never CLI flags, templates, paths, credentials or extra arguments.

Execution is separate from tool discovery and requires one-time user approval
from Cybernova Agent. Nothing here authorizes scanning any provider systems.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from xml.etree import ElementTree

try:
    from .traffic_tools import _definition
except ImportError:
    from traffic_tools import _definition

LAB_ROOT = Path(os.environ.get("CYBERNOVA_LAB_ROOT", "/workspace/cybernova-lab")).resolve()
POLICY = Path(os.environ.get(
    "CYBERNOVA_LAB_SCOPE", str(Path(__file__).with_name("lab_scope.json"))
))
SCAN_TIMEOUT = 125
MAX_OUTPUT = 1_500_000
SCANNER_NAMES = {
    "lab_nmap": "nmap",
    "lab_nuclei": "nuclei",
    "lab_zap_baseline": "zap-baseline.py",
    "lab_nikto": "nikto",
    "lab_testssl": "testssl.sh",
    "lab_ffuf": "ffuf",
    "lab_semgrep": "semgrep",
    "lab_trivy": "trivy",
}
NETWORK_SCANNERS = frozenset({
    "lab_nmap", "lab_nuclei", "lab_zap_baseline", "lab_nikto",
    "lab_testssl", "lab_ffuf",
})
CODE_SCANNERS = frozenset({"lab_semgrep", "lab_trivy"})
SCANNER_TOOLS = [
    _definition("lab_scanner_inventory",
        "Check installed scanner engines and configured lab targets/projects; no scans performed."),
    *[
        _definition(name,
            "Runs installed " + binary + " using a fixed low-impact profile; "
            "only explicitly authorized isolated LAB target IDs. "
            "One-time user approval is mandatory. No custom CLI flags.",
            {"target_id": {"type": "string", "description": "ID from lab_scanner_inventory"}},
            ["target_id"],
        ) for name, binary in SCANNER_NAMES.items() if name in NETWORK_SCANNERS
    ],
    *[
        _definition(name,
            "Offline SAST/SCA scan with " + binary +
            " against an explicitly configured lab project; "
            "fixed rules/profile, one-time user approval, no arbitrary paths.",
            {"project_id": {"type": "string", "description": "ID from lab_scanner_inventory"}},
            ["project_id"],
        ) for name, binary in SCANNER_NAMES.items() if name in CODE_SCANNERS
    ],
]
SCANNER_TOOLS_BY_NAME = {x["name"]: x for x in SCANNER_TOOLS}
SCANNER_TOOL_NAMES = frozenset(SCANNER_TOOLS_BY_NAME)
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")


class ScannerError(ValueError):
    pass


def _policy(policy_path=POLICY):
    try:
        obj = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ScannerError("lab_policy_missing_or_invalid") from exc
    if not isinstance(obj, dict) or obj.get("version") != 1:
        raise ScannerError("unsupported_lab_policy")
    if not isinstance(obj.get("targets"), dict) or not isinstance(obj.get("projects"), dict):
        raise ScannerError("lab_targets_or_projects_missing")
    # Operator must explicitly opt in via config + isolated process environment.
    if obj.get("enabled") is not True:
        raise ScannerError("lab_scanners_disabled")
    if os.environ.get("CYBERNOVA_LAB_ISOLATED") != "1":
        raise ScannerError("lab_network_isolation_not_attested")
    return obj


def _public_tool_installed(name):
    # Do not execute arbitrary model-supplied commands or paths.
    return shutil.which(SCANNER_NAMES[name]) is not None


def inventory(policy_path=POLICY) -> dict:
    engines = [
        {"tool": name, "engine": binary, "installed": _public_tool_installed(name),
         "requires_user_approval": name != "lab_scanner_inventory"}
        for name, binary in SCANNER_NAMES.items()
    ]
    try:
        policy = _policy(policy_path)
        status = "enabled_lab_only"
        target_ids = [k for k in policy["targets"] if NAME.fullmatch(k)][:50]
        project_ids = [k for k in policy["projects"] if NAME.fullmatch(k)][:50]
    except ScannerError as exc:
        status = str(exc)
        target_ids, project_ids = [], []
    return {
        "mode": status, "engines": engines,
        "target_ids": target_ids, "project_ids": project_ids,
        "rules_and_wordlists": "fixed operator-controlled files only",
        "execution": "manual approval per scan; never through inventory",
    }


def _safe_target(policy, target_id):
    if not isinstance(target_id, str) or not NAME.fullmatch(target_id):
        raise ScannerError("invalid_target_id")
    item = policy["targets"].get(target_id)
    if not isinstance(item, dict):
        raise ScannerError("target_not_in_lab_policy")
    url = item.get("url")
    if not isinstance(url, str):
        raise ScannerError("target_url_missing")
    try:
        u = urlsplit(url)
        ip = ipaddress.ip_address(u.hostname or "")
        # Only RFC1918/loopback or IPv6 ULA/loopback lab address space.
        # In particular, CGNAT 100.64/10, public and documentation blocks
        # are NOT accepted as evidence of an isolated test environment.
        lab_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("fc00::/7"),
            ipaddress.ip_network("::1/128"),
        )
        if not any(ip in net for net in lab_ranges):
            raise ScannerError("non_lab_ip_forbidden")
        if u.scheme not in {"http", "https"} or not u.port or not (1 <= u.port <= 65535):
            raise ScannerError("target_requires_explicit_port")
        if u.username or u.password or u.query or u.fragment or u.path not in {"", "/"}:
            raise ScannerError("target_must_be_clean_origin")
    except ScannerError:
        raise
    except (ValueError, TypeError) as exc:
        raise ScannerError("invalid_lab_target") from exc
    return url.rstrip("/"), str(ip), int(u.port)


def _safe_project(policy, project_id):
    if not isinstance(project_id, str) or not NAME.fullmatch(project_id):
        raise ScannerError("invalid_project_id")
    candidate = policy["projects"].get(project_id)
    if not isinstance(candidate, str):
        raise ScannerError("project_not_in_lab_policy")
    path = (LAB_ROOT / "projects" / candidate).resolve(strict=True)
    root = (LAB_ROOT / "projects").resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_dir():
        raise ScannerError("project_outside_lab_root")
    if path == root or path.is_symlink():
        raise ScannerError("invalid_project_directory")
    return path


def _fixed_file(policy, key, directory=True):
    item = policy.get(key)
    if not isinstance(item, str):
        raise ScannerError("missing_fixed_" + key)
    path = (LAB_ROOT / item).resolve(strict=True)
    if not path.is_relative_to(LAB_ROOT):
        raise ScannerError("rules_or_wordlist_outside_lab_root")
    if directory and not path.is_dir():
        raise ScannerError("rules_directory_missing")
    if not directory and (not path.is_file() or path.stat().st_size > 500_000):
        raise ScannerError("fixed_wordlist_missing_or_too_large")
    return path


def _plan(tool, args, policy, work):
    if tool not in SCANNER_NAMES:
        raise ScannerError("unknown_scanner")
    if not isinstance(args, dict) or set(args) != ({
        "target_id"} if tool in NETWORK_SCANNERS else {"project_id"}):
        raise ScannerError("scanner_arguments_must_contain_exact_id")
    if tool in NETWORK_SCANNERS:
        url, ip, port = _safe_target(policy, args["target_id"])
        target = args["target_id"]
    else:
        project = _safe_project(policy, args["project_id"])
        target = args["project_id"]
    base = SCANNER_NAMES[tool]
    binary = shutil.which(base)
    if binary is None:
        raise ScannerError("scanner_binary_not_installed_" + base)
    report = work / "result.json"
    if tool == "lab_nmap":
        # TCP Connect, no scripts, no UDP, no OS fingerprint, one declared port
        command = [binary, "-sT", "-sV", "--version-light", "-Pn", "-n",
                   "-p", str(port), "--max-retries", "1", "--host-timeout",
                   "90s", "-T2", "-oX", "-", ip]
    elif tool == "lab_nuclei":
        rules = _fixed_file(policy, "nuclei_templates")
        command = [binary, "-u", url, "-t", str(rules), "-rl", "3", "-c",
                   "1", "-timeout", "5", "-retries", "0", "-jsonl", "-silent",
                   "-omit-raw", "-omit-template", "-duc", "-ni"]
    elif tool == "lab_zap_baseline":
        # Official packaged baseline scanner, no active ZAP full-scan rules.
        command = [binary, "-t", url, "-m", "1", "-J", str(report), "-I"]
    elif tool == "lab_nikto":
        command = [binary, "-h", url, "-maxtime", "90s", "-timeout", "5s",
                   "-nointeractive", "-Format", "json", "-output", str(report)]
    elif tool == "lab_testssl":
        if not url.startswith("https://"):
            raise ScannerError("testssl_requires_https_lab_target")
        command = [binary, "--quiet", "--fast", "--jsonfile", str(report),
                   ip + ":" + str(port)]
    elif tool == "lab_ffuf":
        wordlist = _fixed_file(policy, "ffuf_wordlist", directory=False)
        # No recursion, no auto redirect, one endpoint and single target.
        command = [binary, "-w", str(wordlist), "-u", url + "/FUZZ",
                   "-rate", "3", "-t", "2", "-timeout", "5", "-maxtime", "60",
                   "-of", "json", "-o", str(report), "-s"]
    elif tool == "lab_semgrep":
        rules = _fixed_file(policy, "semgrep_rules")
        command = [binary, "scan", "--config", str(rules), "--json",
                   "--metrics", "off", "--timeout", "10",
                   "--max-target-bytes", "1000000", str(project)]
    elif tool == "lab_trivy":
        command = [binary, "fs", "--skip-db-update", "--offline-scan",
                   "--scanners", "vuln,misconfig", "--format", "json", str(project)]
    else:
        raise ScannerError("unimplemented_engine")
    return {
        "command": command, "engine": base,
        "target_id": target, "tool": tool,
        "result_path": report, "network": tool in NETWORK_SCANNERS,
    }


def _summary(tool, text, report_bytes):
    """Allowlisted metadata only; never return scanner raw requests or secrets."""
    raw = report_bytes if report_bytes else text.encode("utf-8", "replace")[:MAX_OUTPUT]
    findings = []
    counts = {}
    if tool == "lab_nmap":
        try:
            root = ElementTree.fromstring(raw)
            for port in root.findall(".//port")[:40]:
                service = port.find("service")
                findings.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "state": port.find("state").get("state") if port.find("state") is not None else "unknown",
                    "service": (service.get("name", "")[:50] if service is not None else ""),
                })
        except ElementTree.ParseError:
            pass
    elif tool == "lab_nuclei":
        for line in raw.decode("utf-8", "replace").splitlines()[:200]:
            try:
                row = json.loads(line)
                finding = {
                    "template_id": str(row.get("template-id", ""))[:110],
                    "severity": str((row.get("info") or {}).get("severity", "unknown"))[:25],
                    "type": str(row.get("type", ""))[:25],
                }
                findings.append(finding)
            except (TypeError, ValueError, AttributeError):
                continue
    elif tool == "lab_semgrep":
        try:
            data = json.loads(raw)
            for item in data.get("results", [])[:150]:
                findings.append({"rule": str(item.get("check_id", ""))[:130],
                     "severity": str((item.get("extra") or {}).get("severity","unknown"))[:25],
                     "line": (item.get("start") or {}).get("line")})
        except (ValueError, AttributeError, TypeError):
            pass
    elif tool == "lab_trivy":
        try:
            data = json.loads(raw)
            for target in data.get("Results", [])[:80]:
                vulns = target.get("Vulnerabilities") or []
                mis = target.get("Misconfigurations") or []
                for item in vulns[:50]:
                    findings.append({"vulnerability_id": str(item.get("VulnerabilityID", ""))[:90],
                                     "severity": str(item.get("Severity", "unknown"))[:20]})
                for item in mis[:50]:
                    findings.append({"rule": str(item.get("ID", ""))[:90],
                                     "severity": str(item.get("Severity", "unknown"))[:20]})
        except (ValueError, AttributeError, TypeError):
            pass
    elif tool in {"lab_ffuf", "lab_zap_baseline", "lab_nikto", "lab_testssl"}:
        try:
            data = json.loads(raw)
            if tool == "lab_ffuf":
                for item in data.get("results", [])[:100]:
                    findings.append({"status": item.get("status"),
                                     "length": item.get("length"),
                                     "words": item.get("words")})
            elif tool == "lab_zap_baseline":
                for site in data.get("site", [])[:20]:
                    for alert in site.get("alerts", [])[:100]:
                        findings.append({
                            "plugin_id": str(alert.get("pluginid", ""))[:60],
                            "risk_code": str(alert.get("riskcode", ""))[:10],
                            "confidence": str(alert.get("confidence", ""))[:10],
                        })
            elif tool == "lab_testssl":
                for item in data[:100] if isinstance(data, list) else []:
                    findings.append({"id": str(item.get("id", ""))[:90],
                                     "severity": str(item.get("severity", "unknown"))[:25]})
            else:
                tests = data.get("vulnerabilities", []) if isinstance(data, dict) else []
                findings = [{"id": str(item.get("id", ""))[:70]} for item in tests[:100]]
        except (ValueError, AttributeError, TypeError):
            pass
    for f in findings:
        key = str(f.get("severity") or f.get("state") or f.get("risk_code") or "observed")
        counts[key] = counts.get(key, 0) + 1
    return {"finding_count": len(findings), "counts": counts, "findings": findings[:80],
            "raw_scanner_output_retained": False,
            "assessment": "scanner findings are leads, not verified vulnerabilities"}


def run_scanner(tool: str, args: dict, *, policy_path=POLICY,
                run=subprocess.run) -> dict:
    policy = _policy(policy_path)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cybernova-lab-scan-") as workdir:
        plan = _plan(tool, args, policy, Path(workdir))
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": workdir,
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NUCLEI_DISABLE_UPDATE_CHECK": "true",
            "SEMGREP_SEND_METRICS": "off",
        }
        try:
            process = run(plan["command"], capture_output=True, text=True,
                          timeout=SCAN_TIMEOUT, cwd=workdir, env=env,
                          check=False)
        except subprocess.TimeoutExpired as exc:
            raise ScannerError("scanner_timeout_after_125_seconds") from exc
        except OSError as exc:
            raise ScannerError("scanner_launch_failed_" + type(exc).__name__) from exc
        report = plan["result_path"]
        data = report.read_bytes()[:MAX_OUTPUT] if report.is_file() else b""
        output = str(process.stdout or "")[:MAX_OUTPUT]
        summary = _summary(tool, output, data)
        return {
            "tool": tool, "engine": plan["engine"],
            "target_id": plan["target_id"], "kind": "lab_active" if plan["network"] else "lab_offline",
            "command_profile": "pinned_read_only_lab_profile",
            "exit_code": process.returncode,
            "elapsed_seconds": round(time.monotonic()-started, 2),
            "evidence_sha256": hashlib.sha256(data if data else output.encode()).hexdigest(),
            "result": summary,
            # ZAP packaged scans use 0=pass, 1=warnings, 2=fail;
            # other engines signal execution failures with nonzero codes.
            "scanner_completed": process.returncode in (
                (0, 1, 2) if tool == "lab_zap_baseline" else (0,)
            ),
            "limitations": [
                "Only the operator-configured lab target/project was used as the initial input",
                "Network isolation must be enforced externally; env attestation is not a firewall",
                "Original scanner output discarded; no credentials or HTTP payloads returned",
                "Detected scanner findings require manual validation",
            ],
        }


def dispatch_scanner(name: str, args: dict) -> tuple[dict, bool]:
    try:
        if name == "lab_scanner_inventory":
            return {"ok": True, **inventory()}, False
        if name not in SCANNER_NAMES:
            raise ScannerError("unregistered_scanner")
        outcome = run_scanner(name, args)
        return {"ok": outcome["scanner_completed"], **outcome}, not outcome["scanner_completed"]
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {"ok": False, "error": str(exc)[:180],
                "execution": "not_started_or_failed",
                "tool": name}, True
