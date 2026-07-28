# Stagy API container (roadmap 9.1).
#
# Only the base + web extras are installed. The network and JPEG codecs are
# deliberately excluded: raw-packet crafting has no place behind a web form
# (roadmap §12), and the DCT codec's extra weight buys the API nothing. Both
# self-guard their imports, so `import stagy` works fine without them here.
FROM python:3.12-slim

# Never write .pyc, never buffer stdout — standard container hygiene.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first, in their own layer, so a source-only change does not
# re-run the (slow) dependency resolution.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[web]"

# The `web` package is not part of the wheel (only src/stagy is), so it rides
# along as source and is imported from the working directory.
COPY web ./web

# Drop root. The API touches only per-request temp dirs, nothing it owns.
RUN useradd --create-home --uid 10001 stagy
USER stagy

EXPOSE 8000

# Compose has its own healthcheck, but this makes `docker run` self-describing.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"

CMD ["uvicorn", "web.backend.app:app", "--host", "0.0.0.0", "--port", "8000"]
