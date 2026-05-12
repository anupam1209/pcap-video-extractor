"""
PCAP Video Extractor — FastAPI web application
"""

import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from extractor import (
    CODECS,
    build_gst_pipeline,
    detect_streams,
    run_gst_pipeline,
    tool_available,
)

# ── Config from environment ────────────────────────────────────────────────────

BASE_DIR         = Path(__file__).parent
UPLOAD_DIR       = BASE_DIR / "uploads"
OUTPUT_DIR       = BASE_DIR / "outputs"
STATIC_DIR       = BASE_DIR / "static"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_MB",  "500")) * 1024 * 1024
FILE_TTL_SECS    = int(os.environ.get("FILE_TTL_HOURS", "2"))   * 3600

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="PCAP Video Extractor", version="1.0.0")


@app.on_event("startup")
def _startup():
    tshark_ok = tool_available("tshark")
    gst_ok    = tool_available("gst-launch-1.0")
    print(f"\n  tshark       : {'✓ found' if tshark_ok else '✗ NOT FOUND — install tshark'}")
    print(f"  gst-launch   : {'✓ found' if gst_ok    else '✗ NOT FOUND — install GStreamer'}")
    print(f"  max upload   : {MAX_UPLOAD_BYTES // 1024**2} MB")
    print(f"  file TTL     : {FILE_TTL_SECS // 3600} h")
    print(f"  uploads dir  : {UPLOAD_DIR}")
    print(f"  outputs dir  : {OUTPUT_DIR}\n")
    # Start background cleanup thread
    threading.Thread(target=_cleanup_loop, daemon=True).start()


# ── In-memory job store ────────────────────────────────────────────────────────

_jobs: dict = {}
_lock = threading.Lock()


# ── Pydantic models ────────────────────────────────────────────────────────────

class StreamRequest(BaseModel):
    src_ip:          str
    src_port:        int
    dst_ip:          str
    dst_port:        int
    payload_type:    int
    encoding_name:   str
    clock_rate:      int = 90000
    custom_filename: Optional[str] = None


class ExtractRequest(BaseModel):
    file_id:         str
    streams:         List[StreamRequest]
    pkg_config_path: Optional[str] = None
    gst_plugin_path: Optional[str] = None
    lib_path:        Optional[str] = None


# ── API: health ────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {
        "tshark":     tool_available("tshark"),
        "gstreamer":  tool_available("gst-launch-1.0"),
        "max_upload_mb": MAX_UPLOAD_BYTES // 1024 ** 2,
    }


# ── API: upload & analyse ──────────────────────────────────────────────────────

@app.post("/api/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    name = file.filename or ""
    if not (name.endswith(".pcap") or name.endswith(".pcapng")):
        raise HTTPException(400, "Only .pcap and .pcapng files are supported.")

    if not tool_available("tshark"):
        raise HTTPException(503, "tshark is not installed on this server.")

    # Check Content-Length before reading (fast rejection for huge files)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_BYTES:
        limit_mb = MAX_UPLOAD_BYTES // 1024 ** 2
        raise HTTPException(413, f"File exceeds the {limit_mb} MB upload limit.")

    file_id  = str(uuid.uuid4())
    file_dir = UPLOAD_DIR / file_id
    file_dir.mkdir()
    dest = file_dir / name

    # Stream to disk in chunks, enforce size limit
    try:
        written = 0
        with open(dest, "wb") as f:
            while chunk := await file.read(1024 * 1024):   # 1 MB chunks
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    f.close()
                    shutil.rmtree(file_dir, ignore_errors=True)
                    limit_mb = MAX_UPLOAD_BYTES // 1024 ** 2
                    raise HTTPException(413, f"File exceeds the {limit_mb} MB upload limit.")
                f.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        shutil.rmtree(file_dir, ignore_errors=True)
        raise HTTPException(500, f"Failed to save file: {e}")

    try:
        streams = detect_streams(str(dest))
    except Exception as e:
        shutil.rmtree(file_dir, ignore_errors=True)
        raise HTTPException(500, f"Stream detection failed: {e}")

    return {
        "file_id":  file_id,
        "filename": name,
        "size":     dest.stat().st_size,
        "streams":  streams,
    }


# ── API: pipeline preview (dry-run) ───────────────────────────────────────────

@app.post("/api/pipeline-preview")
def pipeline_preview(req: ExtractRequest):
    """Return the GStreamer command strings that would be run, without executing."""
    file_dir = UPLOAD_DIR / req.file_id
    pcap_files = list(file_dir.glob("*.pcap")) + list(file_dir.glob("*.pcapng"))
    pcap_name = pcap_files[0].name if pcap_files else "capture.pcap"

    previews = []
    for i, s in enumerate(req.streams):
        enc = s.encoding_name.upper()
        cfg = CODECS.get(enc)
        ext = cfg.ext if cfg else "bin"
        out_name = s.custom_filename or _make_filename(
            pcap_name, i, s.src_ip, s.src_port, s.dst_ip, s.dst_port, enc, ext
        )
        try:
            cmd = build_gst_pipeline(
                pcap_file=f"/path/to/{pcap_name}",
                src_ip=s.src_ip, src_port=s.src_port,
                dst_ip=s.dst_ip, dst_port=s.dst_port,
                payload_type=s.payload_type,
                encoding_name=enc,
                clock_rate=s.clock_rate,
                output_file=out_name,
            )
            previews.append({"index": i, "command": cmd, "output": out_name})
        except ValueError as e:
            previews.append({"index": i, "error": str(e)})

    return {"pipelines": previews}


# ── API: start extraction job ──────────────────────────────────────────────────

@app.post("/api/extract")
async def extract(req: ExtractRequest, background_tasks: BackgroundTasks):
    if not tool_available("gst-launch-1.0"):
        raise HTTPException(503, "gst-launch-1.0 is not installed on this server.")

    file_dir = UPLOAD_DIR / req.file_id
    if not file_dir.exists():
        raise HTTPException(404, "Upload not found. Please re-upload the PCAP file.")

    pcap_files = list(file_dir.glob("*.pcap")) + list(file_dir.glob("*.pcapng"))
    if not pcap_files:
        raise HTTPException(404, "PCAP file missing from server.")
    pcap_file = str(pcap_files[0])

    if not req.streams:
        raise HTTPException(400, "No streams selected.")

    job_id  = str(uuid.uuid4())
    out_dir = OUTPUT_DIR / job_id
    out_dir.mkdir()

    stream_statuses = []
    for i, s in enumerate(req.streams):
        enc = s.encoding_name.upper()
        cfg = CODECS.get(enc)
        ext = cfg.ext if cfg else "bin"
        filename = s.custom_filename or _make_filename(
            pcap_file, i, s.src_ip, s.src_port, s.dst_ip, s.dst_port, enc, ext
        )
        stream_statuses.append({
            "index":    i,
            "src":      f"{s.src_ip}:{s.src_port}",
            "dst":      f"{s.dst_ip}:{s.dst_port}",
            "codec":    enc,
            "filename": filename,
            "status":   "pending",
            "log":      "",
        })

    with _lock:
        _jobs[job_id] = {
            "status":     "pending",
            "total":      len(req.streams),
            "done":       0,
            "streams":    stream_statuses,
            "outputs":    [],
            "errors":     [],
            "created_at": time.time(),
        }

    background_tasks.add_task(
        _run_job,
        job_id, pcap_file, req.streams, stream_statuses, str(out_dir),
        req.pkg_config_path, req.gst_plugin_path, req.lib_path,
    )

    return {"job_id": job_id}


# ── API: job status ────────────────────────────────────────────────────────────

@app.get("/api/job/{job_id}")
def job_status(job_id: str):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    return job


# ── API: stream log ───────────────────────────────────────────────────────────

@app.get("/api/log/{job_id}/{stream_index}")
def stream_log(job_id: str, stream_index: int):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    streams = job.get("streams", [])
    if stream_index >= len(streams):
        raise HTTPException(404, "Stream index out of range.")
    s = streams[stream_index]
    return {"log": s.get("log", ""), "status": s.get("status", ""), "filename": s.get("filename", "")}


# ── API: download ──────────────────────────────────────────────────────────────

@app.get("/api/download/{job_id}/{filename}")
def download(job_id: str, filename: str):
    safe = Path(filename).name          # strip any path traversal
    path = OUTPUT_DIR / job_id / safe
    if not path.exists():
        raise HTTPException(404, "File not found.")
    return FileResponse(path=str(path), filename=safe, media_type="application/octet-stream")


# ── API: manual cleanup ────────────────────────────────────────────────────────

@app.delete("/api/cleanup/{file_id}")
def cleanup(file_id: str):
    d = UPLOAD_DIR / file_id
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
    return {"ok": True}


# ── Background: job runner ─────────────────────────────────────────────────────

def _run_job(
    job_id:          str,
    pcap_file:       str,
    streams:         List[StreamRequest],
    statuses:        list,
    out_dir:         str,
    pkg_config_path: Optional[str],
    gst_plugin_path: Optional[str],
    lib_path:        Optional[str],
) -> None:
    with _lock:
        _jobs[job_id]["status"] = "running"

    for i, (s, st) in enumerate(zip(streams, statuses)):
        with _lock:
            _jobs[job_id]["streams"][i]["status"] = "running"

        output_path = os.path.join(out_dir, st["filename"])

        try:
            pipeline = build_gst_pipeline(
                pcap_file=pcap_file,
                src_ip=s.src_ip,   src_port=s.src_port,
                dst_ip=s.dst_ip,   dst_port=s.dst_port,
                payload_type=s.payload_type,
                encoding_name=s.encoding_name,
                clock_rate=s.clock_rate,
                output_file=output_path,
            )
            rc, log = run_gst_pipeline(
                pipeline, pkg_config_path, gst_plugin_path, lib_path
            )
        except ValueError as e:
            rc, log = -1, str(e)

        file_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
        with _lock:
            _jobs[job_id]["done"] += 1
            if rc == 0 and file_size > 0:
                _jobs[job_id]["streams"][i]["status"] = "completed"
                _jobs[job_id]["outputs"].append({
                    "stream_index": i,
                    "filename":     st["filename"],
                    "size":         file_size,
                    "job_id":       job_id,
                })
            else:
                reason = (
                    f"GStreamer exited with code {rc}"
                    if rc != 0 else
                    "GStreamer succeeded but output file is empty (stream may have no keyframes)"
                )
                _jobs[job_id]["streams"][i]["status"] = "failed"
                _jobs[job_id]["streams"][i]["log"]    = log  # full log, not truncated
                _jobs[job_id]["errors"].append({
                    "stream_index": i,
                    "message":      reason,
                })

    with _lock:
        _jobs[job_id]["status"] = "completed"


# ── Background: periodic file cleanup ─────────────────────────────────────────

def _cleanup_loop() -> None:
    """Delete uploads and outputs older than FILE_TTL_SECS every hour."""
    while True:
        time.sleep(3600)
        _purge_old(UPLOAD_DIR)
        _purge_old(OUTPUT_DIR)


def _purge_old(base: Path) -> None:
    cutoff = time.time() - FILE_TTL_SECS
    for item in base.iterdir():
        if item.is_dir() and item.stat().st_mtime < cutoff:
            shutil.rmtree(item, ignore_errors=True)
            # Also evict the in-memory job entry if applicable
            with _lock:
                stale = [jid for jid, j in _jobs.items()
                         if j.get("created_at", 0) < cutoff]
                for jid in stale:
                    del _jobs[jid]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_filename(
    pcap_file: str, idx: int,
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    enc: str, ext: str,
) -> str:
    base = Path(pcap_file).stem
    src  = src_ip.replace(".", "_").replace(":", "_")
    dst  = dst_ip.replace(".", "_").replace(":", "_")
    return f"{base}_{src}_{src_port}_to_{dst}_{dst_port}_{enc.lower()}.{ext}"


# ── Static frontend ────────────────────────────────────────────────────────────

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
