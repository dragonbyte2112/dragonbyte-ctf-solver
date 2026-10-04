FROM python:3.12-slim

# Real CTF tools the solvers actually invoke as subprocesses - not simulated.
# file/strings/objdump/unzip/tar/openssl/gcc are not installed here since this
# image only needs to RUN the API, not compile test fixtures.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libimage-exiftool-perl binwalk steghide zbar-tools p7zip-full \
    file binutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py analyzer.py ai_engine.py ./
COPY solvers/ ./solvers/

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
