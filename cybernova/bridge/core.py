"""Read-only, fixed diagnostic commands. No arbitrary shell."""
import platform, subprocess, sys
from pathlib import Path
PRESETS={
 "gpu":["nvidia-smi","--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu,driver_version","--format=csv,noheader"],
 "disk":["df","-h","/workspace"],
 "memory":["free","-h"],
 "python":[sys.executable,"--version"],
 "ollama":["ollama","--version"],
 "torch_cuda":[str(Path("/venv/main/bin/python") if Path("/venv/main/bin/python").exists() else Path(sys.executable)),"-c","import torch; print(torch.__version__); print(torch.cuda.is_available())"],
}
def health():
 return {"bridge":"CyberSec Vast Bridge","status":"ready","python":platform.python_version(),"tools":list(PRESETS)}
def run_diagnostic(kind):
 if kind not in PRESETS: return {"ok":False,"error":"Unknown diagnostic"}
 try:
  p=subprocess.run(PRESETS[kind],shell=False,capture_output=True,text=True,timeout=45 if kind=="torch_cuda" else 15,check=False,errors="replace")
  output=(p.stdout+"\n"+p.stderr).strip()
  return {"ok":p.returncode==0,"kind":kind,"exit_code":p.returncode,"output":output[:6000],"truncated":len(output)>6000}
 except (FileNotFoundError,subprocess.TimeoutExpired) as exc:
  return {"ok":False,"kind":kind,"error":type(exc).__name__}
