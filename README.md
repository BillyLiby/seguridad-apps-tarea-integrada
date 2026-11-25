# Seguridad en Aplicaciones: tarea integrada

API REST de notas (FastAPI) con auditoría, remediación y automatización de controles de seguridad.
Repositorio: https://github.com/BillyLiby/seguridad-apps-tarea-integrada

> Laboratorio académico. Cuentas y datos ficticios. Todo se ejecuta en local.
> **`app_vulnerable/` es una versión deliberadamente vulnerable: no desplegar ni exponer a Internet.**

## Guía rápida para el evaluador
Requisitos: Windows con PowerShell, Python 3.12, Git y Docker Desktop (Docker solo para ZAP, Trivy y OPA).
```powershell
git clone https://github.com/BillyLiby/seguridad-apps-tarea-integrada.git
cd seguridad-apps-tarea-integrada
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest
```
Resultado esperado: **10 passed**. Después:
```powershell
$env:APP_TARGET="app_vulnerable"; pytest        # esperado: 3 failed (t2, t6, t7) y 7 passed
Remove-Item Env:APP_TARGET
```
La ejecución en CI está en la pestaña **Actions** del repositorio: el run del commit `01de234` (bloquea) y el del commit `680cfa2` (pasa).
Los resultados completos, con capturas, están en `evidencias/` y el informe técnico acompaña la entrega.

## Estructura
| Ruta | Contenido |
|---|---|
| `app_segura/` | API corregida |
| `app_vulnerable/` | Variante didáctica con 2 defectos (BOLA/IDOR e inyección SQL), aislada |
| `tests/` | 10 pruebas de seguridad (pytest) |
| `semgrep/rules/` | Regla propia `lab-sqlite-dynamic-sql` y sus casos de prueba |
| `sbom/` | SBOM CycloneDX 1.5 (`sbom.cdx.json` después; `sbom_before.cdx.json` antes) |
| `policy/` | Política OPA (Rego), sus pruebas y entradas de ejemplo |
| `terraform/` | `insecure/` (condición insegura de laboratorio) y `secure/` (corregida) |
| `.github/workflows/security.yml` | Pipeline CI/CD |
| `Dockerfile`, `.dockerignore` | Imagen de la versión segura |
| `reports/` | Reportes generados (Semgrep, pip-audit, ZAP, diff) |
| `docs/` | Documentos por sección (3.1 a 3.7) |
| `evidencias/` | Capturas de pantalla (ver índice más abajo) |
| `tools/` | Scripts auxiliares |

## Entornos virtuales
Las herramientas se separan en tres entornos por conflictos reales de dependencias:
| Entorno | Archivo | Para qué |
|---|---|---|
| `.venv` | `requirements-dev.txt` | La aplicación y `pytest` |
| `.venv-semgrep` | `requirements-semgrep.txt` | Semgrep |
| `.venv-tools` | `requirements-tools.txt` | pip-audit, cyclonedx-py, Checkov, pipdeptree |
```powershell
py -m venv .venv-semgrep
.venv-semgrep\Scripts\python.exe -m pip install -r requirements-semgrep.txt
py -m venv .venv-tools
.venv-tools\Scripts\python.exe -m pip install -r requirements-tools.txt
```

## Reproducción de los controles
**Pruebas (3.3b, 3.4)**
```powershell
pytest                                            # versión segura: 10 passed
$env:APP_TARGET="app_vulnerable"; pytest          # fallan t2, t6 y t7
Remove-Item Env:APP_TARGET
pytest tests/test_security.py::test_t7_request_flow_trace -s   # traza del flujo
```
**SAST (3.2a, 3.2b)**
```powershell
$env:PYTHONUTF8="1"
.venv-semgrep\Scripts\semgrep.exe --test semgrep/rules
.venv-semgrep\Scripts\semgrep.exe scan --metrics=off --config p/python --config semgrep/rules app_vulnerable
.venv-semgrep\Scripts\semgrep.exe scan --metrics=off --config p/python --config semgrep/rules app_segura
```
**SCA y SBOM (3.2c, 3.2d)**
```powershell
.venv-tools\Scripts\pip-audit.exe -r requirements.txt
py -m venv .venv-runtime; .venv-runtime\Scripts\python -m pip install -r requirements.txt
.venv-tools\Scripts\cyclonedx-py.exe environment .venv-runtime --sv 1.5 --of JSON -o sbom/sbom.cdx.json
.venv-tools\Scripts\python.exe tools\validate_sbom.py sbom\sbom.cdx.json
```
**Aplicación en ejecución, sondeo y DAST (3.3a)**
```powershell
$env:SECRET_KEY="clave-de-laboratorio-de-al-menos-32-caracteres-xyz"; $env:DB_PATH="lab.db"
python -c "from app_segura.main import init_db; init_db()"
uvicorn app_segura.main:app --host 127.0.0.1 --port 8000
# en otra ventana (con .venv activo):
python tools\probe_api.py
docker run --rm -v "${PWD}\reports:/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8000 -r zap_baseline.html -J zap_baseline.json -I
```
Para la versión vulnerable (puerto 8001): `DB_PATH=lab_vuln.db`, `init_db` de `app_vulnerable.main` y `uvicorn app_vulnerable.main:app --port 8001`.

**Contenedor, IaC y política (3.6)**
```powershell
docker build -t notas-api:lab .
docker save notas-api:lab -o $env:TEMP\notas-api.tar
docker run --rm -v trivy-cache:/root/.cache -v "${env:TEMP}:/w" aquasec/trivy:latest image --input /w/notas-api.tar --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1

.venv-tools\Scripts\checkov.cmd -d terraform/insecure --framework terraform --compact --skip-check CKV2_AWS_5
.venv-tools\Scripts\checkov.cmd -d terraform/secure   --framework terraform --compact --skip-check CKV2_AWS_5

docker run --rm -v "${PWD}\policy:/p" openpolicyagent/opa:1.0.0 test /p/deploy.rego /p/deploy_test.rego -v
docker run --rm -v "${PWD}\policy:/p" openpolicyagent/opa:1.0.0 eval -i /p/inputs/denied.json -d /p/deploy.rego "data.lab.deploy.deny[_]" --fail-defined --format pretty
```
Una denegación de OPA devuelve el código de salida 1 (`--fail-defined`), que detiene el pipeline.

## CI/CD (3.5)
Archivo: `.github/workflows/security.yml`. Los pasos "BLOQUEO" detienen el flujo; los "ADVERTENCIA" nunca bloquean.
| Ejecución | Commit | Resultado |
|---|---|---|
| Run #1 (bloquea) | `01de234` | Puertas 3 (pip-audit) y 6 (Trivy) en rojo |
| Run #2 (corregido) | `680cfa2` | 7 de 7 en verde |

## Índice de evidencias (carpeta `evidencias/`)
| Captura | Contenido | Sección |
|---|---|---|
| C1, C2 | `pytest` segura (10 passed) y vulnerable (3 failed) | 3.3b, 3.4 |
| C3a, C3b | Traza del flujo de `t7` en segura y vulnerable | 3.3c |
| C4 a C6 | Semgrep: prueba de la regla; escaneos vulnerable y segura | 3.2a, 3.2b |
| C7, C8, C9 | pip-audit (antes); pipdeptree; validación del SBOM (antes) | 3.2c, 3.2d |
| C10, C11, C12 | Sondeo de la API; ZAP en consola; reporte HTML de ZAP | 3.3a |
| C13, C14 | Diff vulnerable vs segura; sondeo de la versión vulnerable | 3.4 |
| C16, C17, C17b | Run #1 en rojo y sus logs | 3.5 |
| C18, C19, C20, C20a, C21, C21b | Después del fix: pytest, pip-audit, Trivy, causa de `setuptools`, SBOM, `/health` | 3.2, 3.6 |
| C22 | Run #2 en verde | 3.5 |

## Limitaciones
Ver `docs/3.7_indicadores_y_decision.md` (limitaciones de medición y riesgos residuales).
