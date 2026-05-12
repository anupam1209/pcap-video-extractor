"""
Core extraction logic shared by the CLI tool and the web app.

H264/H265 extraction uses a two-step approach because GStreamer's muxers (mp4mux,
matroskamux) fail to write frames reliably when the RTP stream contains in-band
SPS/PPS negotiation changes (common in video-call recordings). The fix:
  Step 1 – GStreamer: pcap → rtpXXXdepay → raw Annex-B byte-stream → temp file
  Step 2 – ffmpeg:   temp file → -c:v copy → final .mp4

All other codecs (VP8/VP9/JPEG/H263) go through a direct single-step GStreamer
pipeline because their muxers (webmmux, avimux) handle the streams without issue.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Codec registry ─────────────────────────────────────────────────────────────

@dataclass
class CodecConfig:
    depay: str
    mux: str
    ext: str
    clock_rate: int = 90000
    parse: Optional[str] = None
    # Two-step fields: if raw_caps is set, extract raw bytes then ffmpeg-mux
    raw_caps: Optional[str] = None        # caps filter after depay (byte-stream)
    ffmpeg_fmt: Optional[str] = None      # ffmpeg -f <format> for raw input


CODECS: Dict[str, CodecConfig] = {
    # H264/H265: two-step via ffmpeg because GStreamer muxers drop frames when
    # the encoder changes SPS mid-call (resolution/bitrate adaptation).
    "H264": CodecConfig(
        depay="rtph264depay", mux="mp4mux", ext="mp4",
        raw_caps="video/x-h264,stream-format=byte-stream,alignment=au",
        ffmpeg_fmt="h264",
    ),
    "H265": CodecConfig(
        depay="rtph265depay", mux="mp4mux", ext="mp4",
        raw_caps="video/x-h265,stream-format=byte-stream,alignment=au",
        ffmpeg_fmt="hevc",
    ),
    # Direct single-step GStreamer pipelines for the rest
    "VP8":       CodecConfig("rtpvp8depay",   "webmmux", "webm"),
    "VP9":       CodecConfig("rtpvp9depay",   "webmmux", "webm"),
    "MP4V-ES":   CodecConfig("rtpmp4vdepay",  "avimux",  "avi",  parse="mpeg4videoparse"),
    "JPEG":      CodecConfig("rtpjpegdepay",  "avimux",  "avi"),
    "H263":      CodecConfig("rtph263depay",  "avimux",  "avi"),
    "H263-1998": CodecConfig("rtph263pdepay", "avimux",  "avi"),
    "H261":      CodecConfig("rtph261depay",  "avimux",  "avi"),
}

_VIDEO_CODECS = set(CODECS.keys()) | {"MPV", "MP1S", "MP2T", "BMPEG", "THEORA", "AV1"}
_AUDIO_CODECS = {
    "PCMU", "PCMA", "AMR", "AMR-WB", "G722", "G726", "G729", "OPUS",
    "SPEEX", "CN", "G723", "G728", "G711", "TELEPHONE-EVENT", "EVS",
    "RED", "G7221", "GSM", "MPA", "L16",
}

STATIC_PT: Dict[int, Tuple[str, str]] = {
    0:  ("audio", "PCMU"),  3:  ("audio", "GSM"),
    4:  ("audio", "G723"),  8:  ("audio", "PCMA"),
    9:  ("audio", "G722"),  14: ("audio", "MPA"),
    18: ("audio", "G729"),  26: ("video", "JPEG"),
    31: ("video", "H261"),  32: ("video", "MPV"),
    33: ("video", "MP2T"),  34: ("video", "H263"),
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _tshark(*args: str) -> Optional[str]:
    try:
        r = subprocess.run(["tshark"] + list(args), capture_output=True, text=True, timeout=120)
        return r.stdout if r.returncode in (0, 1) else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _classify(encoding_name: str, clock_rate: int) -> str:
    enc = encoding_name.upper()
    if enc in _VIDEO_CODECS:
        return "video"
    if enc in _AUDIO_CODECS:
        return "audio"
    return "video" if clock_rate == 90000 else "audio" if clock_rate <= 48000 else "unknown"


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ── SDP parsing ────────────────────────────────────────────────────────────────

def parse_sdp_mappings(pcap_file: str) -> Dict[int, dict]:
    """Return {pt: {media, encoding_name, clock_rate}} from SDP in the capture."""
    mappings: Dict[int, dict] = {
        pt: {"media": m, "encoding_name": enc, "clock_rate": 90000}
        for pt, (m, enc) in STATIC_PT.items()
    }

    out = _tshark("-r", pcap_file, "-o", "rtp.heuristic_rtp:TRUE", "-2",
                  "-Y", "sdp", "-T", "fields", "-e", "sdp.rtpmap")
    if not out or not out.strip():
        return mappings

    for line in out.splitlines():
        for entry in re.split(r"[,\n]+", line):
            m = re.match(r"^(\d+)\s+([\w\-]+)/(\d+)", entry.strip())
            if m:
                pt, enc, rate = int(m.group(1)), m.group(2).upper(), int(m.group(3))
                mappings[pt] = {
                    "media": _classify(enc, rate),
                    "encoding_name": enc,
                    "clock_rate": rate,
                }
    return mappings


# ── Stream detection ───────────────────────────────────────────────────────────

def detect_streams(pcap_file: str) -> List[dict]:
    """Return a list of stream dicts suitable for JSON serialisation."""
    out = _tshark(
        "-r", pcap_file,
        "-o", "rtp.heuristic_rtp:TRUE",
        "-2",
        "-Y", "rtp",
        "-T", "fields",
        "-e", "ip.src",    "-e", "udp.srcport",
        "-e", "ip.dst",    "-e", "udp.dstport",
        "-e", "rtp.p_type", "-e", "rtp.ssrc",
    )
    if not out:
        return []

    sdp_map = parse_sdp_mappings(pcap_file)
    index: Dict[tuple, dict] = {}

    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < 5 or not all(cols[:5]):
            continue
        try:
            key = (cols[0], int(cols[1]), cols[2], int(cols[3]), int(cols[4]))
        except ValueError:
            continue

        if key not in index:
            pt = int(cols[4])
            info = sdp_map.get(pt, {})
            index[key] = {
                "src_ip":        cols[0],
                "src_port":      int(cols[1]),
                "dst_ip":        cols[2],
                "dst_port":      int(cols[3]),
                "payload_type":  pt,
                "ssrc":          cols[5].strip() if len(cols) > 5 else "",
                "packets":       0,
                "media":         info.get("media", "unknown"),
                "encoding_name": info.get("encoding_name"),
                "clock_rate":    info.get("clock_rate", 90000),
            }
        index[key]["packets"] += 1

    return list(index.values())


# ── Pipeline builder (for preview and single-step codecs) ─────────────────────

def build_gst_pipeline(
    pcap_file: str,
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    payload_type: int,
    encoding_name: str,
    clock_rate: int,
    output_file: str,
) -> str:
    """
    Build a GStreamer pipeline string.
    For H264/H265 this produces the raw extraction step (output_file should be
    the temp path); use extract_rtp_to_file() for the full two-step pipeline.
    """
    enc = encoding_name.upper()
    cfg = CODECS.get(enc)
    if not cfg:
        raise ValueError(f"Unsupported codec '{enc}'. Supported: {', '.join(CODECS)}")

    caps = (
        f"application/x-rtp,media=video"
        f",clock-rate={clock_rate}"
        f",encoding-name={enc}"
        f",payload={payload_type}"
    )
    parts = [
        f'filesrc location="{pcap_file}"',
        f'pcapparse src-ip="{src_ip}" src-port={src_port} dst-ip="{dst_ip}" dst-port={dst_port}',
        f'"{caps}"',
        cfg.depay,
    ]

    if cfg.raw_caps:
        # Raw byte-stream extraction — no mux, just dump bytes to file
        parts += [f'"{cfg.raw_caps}"', f'filesink location="{output_file}"']
    else:
        if cfg.parse:
            parts.append(cfg.parse)
        parts += [cfg.mux, f'filesink location="{output_file}"']

    return "gst-launch-1.0 -e \\\n    " + " ! \\\n    ".join(parts)


# ── High-level extractor (GStreamer + optional ffmpeg mux step) ────────────────

def extract_rtp_to_file(
    pcap_file: str,
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    payload_type: int,
    encoding_name: str,
    clock_rate: int,
    output_file: str,
    pkg_config_path: Optional[str] = None,
    gst_plugin_path: Optional[str] = None,
    lib_path: Optional[str] = None,
) -> Tuple[int, str]:
    """
    Extract one RTP stream from a PCAP file to a video file.
    Returns (returncode, combined_log).
    """
    enc = encoding_name.upper()
    cfg = CODECS.get(enc)
    if not cfg:
        return -1, f"Unsupported codec '{enc}'. Supported: {', '.join(CODECS)}"

    if cfg.raw_caps and cfg.ffmpeg_fmt:
        return _extract_two_step(
            pcap_file, src_ip, src_port, dst_ip, dst_port,
            payload_type, enc, clock_rate, output_file, cfg,
            pkg_config_path, gst_plugin_path, lib_path,
        )

    # Single-step: direct GStreamer mux
    pipeline = build_gst_pipeline(
        pcap_file, src_ip, src_port, dst_ip, dst_port,
        payload_type, enc, clock_rate, output_file,
    )
    return run_gst_pipeline(pipeline, pkg_config_path, gst_plugin_path, lib_path)


def _extract_two_step(
    pcap_file: str,
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    payload_type: int,
    enc: str,
    clock_rate: int,
    output_file: str,
    cfg: CodecConfig,
    pkg_config_path: Optional[str],
    gst_plugin_path: Optional[str],
    lib_path: Optional[str],
) -> Tuple[int, str]:
    """Two-step extraction for H264/H265: GStreamer → raw bytes → ffmpeg → MP4."""
    tmp_file = output_file + f".tmp.{enc.lower()}"
    log_parts: List[str] = []

    try:
        # Step 1: GStreamer raw byte-stream extraction
        gst_cmd = build_gst_pipeline(
            pcap_file, src_ip, src_port, dst_ip, dst_port,
            payload_type, enc, clock_rate, tmp_file,
        )
        log_parts.append(f"=== Step 1: GStreamer raw extraction ===\n{gst_cmd}\n")
        rc, gst_log = run_gst_pipeline(gst_cmd, pkg_config_path, gst_plugin_path, lib_path)
        log_parts.append(gst_log)

        if rc != 0:
            return rc, "\n".join(log_parts)

        tmp_size = os.path.getsize(tmp_file) if os.path.exists(tmp_file) else 0
        if tmp_size == 0:
            return -1, "\n".join(log_parts) + "\nGStreamer produced an empty raw file."

        # Step 2: ffmpeg remux into final container
        ffmpeg_cmd = (
            f'ffmpeg -y -f {cfg.ffmpeg_fmt} -i "{tmp_file}" '
            f'-c:v copy "{output_file}" 2>&1'
        )
        log_parts.append(f"\n=== Step 2: ffmpeg remux ===\n{ffmpeg_cmd}\n")
        try:
            result = subprocess.run(
                ffmpeg_cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=300,
            )
            log_parts.append(result.stdout)
            return result.returncode, "\n".join(log_parts)
        except subprocess.TimeoutExpired:
            return -1, "\n".join(log_parts) + "\nffmpeg timed out after 300 s."

    finally:
        if os.path.exists(tmp_file):
            os.unlink(tmp_file)


# ── Low-level GStreamer runner ─────────────────────────────────────────────────

def run_gst_pipeline(
    pipeline: str,
    pkg_config_path: Optional[str] = None,
    gst_plugin_path: Optional[str] = None,
    lib_path: Optional[str] = None,
) -> Tuple[int, str]:
    """Run a gst-launch pipeline string. Returns (returncode, combined_output)."""
    env = os.environ.copy()
    if pkg_config_path:
        env["PKG_CONFIG_PATH"] = f"{pkg_config_path}:{env.get('PKG_CONFIG_PATH', '')}"
    if gst_plugin_path:
        env["GST_PLUGIN_PATH"] = gst_plugin_path
    if lib_path:
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{env.get('LD_LIBRARY_PATH', '')}"
    env.setdefault("GST_DEBUG", "3")

    try:
        result = subprocess.run(
            pipeline, shell=True, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=600,
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return -1, f"Pipeline timed out after 600 s.\n{out}"
