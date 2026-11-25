# Imagen base: python:3.12-slim-bookworm
#  - Misma version mayor de Python con la que se prueban las pruebas (3.12).
#  - Variante "slim" sobre Debian estable: menos paquetes del sistema = menor superficie de ataque
#    y menos CVE que la imagen completa. Etiqueta fija (no "latest") para reproducibilidad.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DB_PATH=/data/notes.db

WORKDIR /app

# Dependencias primero para aprovechar la cache de capas
COPY requirements.txt .
RUN pip install -r requirements.txt

# Solo el codigo de la version SEGURA (nunca app_vulnerable)
COPY app_segura ./app_segura

# Privilegios minimos: usuario sin privilegios y directorio de datos propio
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir /data && chown appuser:appuser /data
USER 10001

EXPOSE 8000

# SECRET_KEY NO se incluye en la imagen: se inyecta en tiempo de ejecucion (-e SECRET_KEY=...)
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"

CMD ["uvicorn", "app_segura.main:app", "--host", "0.0.0.0", "--port", "8000"]
