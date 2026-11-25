"""Genera la entrada de OPA a partir de la configuracion REAL del proyecto (Dockerfile + requirements.txt).
Uso: python tools/build_policy_input.py [archivo_salida]   (por defecto policy/inputs/actual.json)"""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
base_image, user, healthcheck = "", "", False
for line in (root / "Dockerfile").read_text(encoding="utf-8").splitlines():
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    parts = s.split()
    key = parts[0].upper()
    if key == "FROM":
        base_image = parts[1]
    elif key == "USER":
        user = parts[1].split(":")[0]
    elif key == "HEALTHCHECK" and "NONE" not in s.upper():
        healthcheck = True

deps = []
for line in (root / "requirements.txt").read_text(encoding="utf-8").splitlines():
    s = line.split("#")[0].strip()
    if s and not s.startswith("-"):
        deps.append(s)

data = {"container": {"user": user, "base_image": base_image, "healthcheck": healthcheck}, "dependencies": deps}
out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else root / "policy" / "inputs" / "actual.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Entrada de politica escrita en {out}")
print(json.dumps(data, indent=2))
