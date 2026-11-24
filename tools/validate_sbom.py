"""Valida sbom/sbom.cdx.json contra el esquema CycloneDX JSON y resume sus componentes."""
import json
import pathlib
import sys

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "sbom/sbom.cdx.json")
text = path.read_text(encoding="utf-8")
doc = json.loads(text)
version = doc.get("specVersion", "1.5")
schema = SchemaVersion.from_version(version)

error = JsonStrictValidator(schema).validate_str(text)
print(f"Archivo: {path}")
print(f"bomFormat: {doc.get('bomFormat')}  specVersion: {version}")
print("RESULTADO:", "VALIDO (cumple el esquema CycloneDX)" if error is None else f"INVALIDO -> {error}")
print(f"Componentes: {len(doc.get('components', []))}")
for c in sorted(doc.get("components", []), key=lambda c: c["name"].lower()):
    print(f"  - {c['name']}=={c.get('version')}  {c.get('purl', '')}")
sys.exit(0 if error is None else 1)
