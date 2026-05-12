"""
Core extraction logic shared by the CLI tool and the web app.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple


# ── Codec registry ─────────────────────────────────────────────────────────────

@dataclass
class CodecConfig:
    depay: str
    mux: str
    ext: str
    clock_rate: int = 90000
    parse: Optional[str] = None


CODECS: Dict[str, CodecConfig] = {
    # matroskamux (.mkv) accepts H264/H265 in byte-stream format and does not
    # require SPS/PPS to appear before the first IDR frame, unlike mp4mux.
    # config-interval=-1 on h264parse tells it to pass frames through even
    # before it has seen SPS/PPS (it will prepend them to IDR frames once found).
    "H264":      CodecConfig("rtph264depay",  "matroskamux", "mkv",  parse="h264parse config-interval=-1"),
    "H265":      CodecConfig("rtph265depay",  "matroskamux", "mkv",  parse="h265parse config-interval=-1"),
    "VP8":       CodecConfig("rtpvp8depay",   "webmmux",     "webm"),
    "VP9":       CodecConfig("rtpvp9depay",   "webmmux",     "webm"),
    "MP4V-ES":   CodecConfig("rtpmp4vdepay",  "matroskamux", "mkv",  parse="mpeg4videoparse"),
    "JPEG":      CodecConfig("rtpjpegdepay",  "avimux",      "avi"),
    "H263":      CodecConfig("rtph263depay",  "avimux",      "avi"),
    "H263-1998": CodecConfig("rtph263pdepay", "avimux",      "avi"),
    "H261":      CodecConfig("rtph261depay",  "avimux",      "avi"),
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
    """
    Return a list of stream dicts suitable for JSON serialisation.
    Each dict includes media type and codec resolved from SDP or heuristics.
    """
    # Enable RTP heuristic dissector so tshark decodes UDP-as-RTP even when
    # ports are non-standard and no Wireshark decode-as hints are present.
    out = _tshark(
        "-r", pcap_file,
        "-o", "rtp.heuristic_rtp:TRUE",
        "-2",               # two-pass analysis improves protocol identification
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


# ── Pipeline builder ───────────────────────────────────────────────────────────

def build_gst_pipeline(
    pcap_file: str,
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    payload_type: int,
    encoding_name: str,
    clock_rate: int,
    output_file: str,
) -> str:
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
    if cfg.parse:
        parts.append(cfg.parse)
    parts += [cfg.mux, f'filesink location="{output_file}"']
    return "gst-launch-1.0 -ve \\\n    " + " ! \\\n    ".join(parts)


# ── Pipeline runner ────────────────────────────────────────────────────────────

def run_gst_pipeline(
    pipeline: str,
    pkg_config_path: Optional[str] = None,
    gst_plugin_path: Optional[str] = None,
    lib_path: Optional[str] = None,
) -> Tuple[int, str]:
    """Run the pipeline. Returns (returncode, combined_output)."""
    env = os.environ.copy()
    if pkg_config_path:
        env["PKG_CONFIG_PATH"] = f"{pkg_config_path}:{env.get('PKG_CONFIG_PATH', '')}"
    if gst_plugin_path:
        env["GST_PLUGIN_PATH"] = gst_plugin_path
    if lib_path:
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{env.get('LD_LIBRARY_PATH', '')}"
    # GST_DEBUG=3 captures element errors/warnings without flooding with trace output.
    env.setdefault("GST_DEBUG", "3")

    try:
        result = subprocess.run(
            pipeline, shell=True, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=600,
        )
        return result.returncode, result.stdout
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return -1, f"Pipeline timed out after 600 s.\n{output}"
