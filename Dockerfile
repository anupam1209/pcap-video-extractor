FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 python3-pip \
    # Wireshark CLI (tshark) for PCAP/RTP stream analysis
    tshark \
    # GStreamer core + plugins needed for RTP video extraction from PCAP
    gstreamer1.0-tools \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    gstreamer1.0-plugins-ugly \
    gstreamer1.0-libav \
    # ffmpeg: used to remux raw H264/H265 byte-streams into MP4 containers
    ffmpeg \
  && rm -rf /var/lib/apt/lists/*

# Allow tshark to read pcap files without root (dumpcap needs this group)
RUN usermod -aG wireshark root 2>/dev/null || true

WORKDIR /app

# ── Python dependencies (separate layer for cache efficiency) ──────────────────
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────────────────────
COPY extractor.py main.py ./
COPY static/ ./static/

# Persistent storage dirs (mount a volume here in production)
RUN mkdir -p uploads outputs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["python3", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--timeout-keep-alive", "120"]
