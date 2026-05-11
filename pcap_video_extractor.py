#!/usr/bin/env python3
"""
PCAP Video Extractor
Automatically detect and extract RTP video streams from any .pcap file.
Uses tshark for stream/SDP analysis and GStreamer for decoding.
"""

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
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
    "H264":      CodecConfig("rtph264depay",  "mp4mux",  "mp4",  parse="h264parse"),
    "H265":      CodecConfig("rtph265depay",  "mp4mux",  "mp4",  parse="h265parse"),
    "VP8":       CodecConfig("rtpvp8depay",   "webmmux", "webm"),
    "VP9":       CodecConfig("rtpvp9depay",   "webmmux", "webm"),
    "MP4V-ES":   CodecConfig("rtpmp4vdepay",  "mp4mux",  "mp4",  parse="mpeg4videoparse"),
    "JPEG":      CodecConfig("rtpjpegdepay",  "avimux",  "avi"),
    "H263":      CodecConfig("rtph263depay",  "avimux",  "avi"),
    "H263-1998": CodecConfig("rtph263pdepay", "avimux",  "avi"),
    "H261":      CodecConfig("rtph261depay",  "avimux",  "avi"),
}

# CLI --codec aliases → canonical encoding-name
CODEC_ALIASES: Dict[str, str] = {
    "h264": "H264", "avc": "H264",
    "h265": "H265", "hevc": "H265",
    "vp8":  "VP8",
    "vp9":  "VP9",
    "mpeg4": "MP4V-ES", "mp4v": "MP4V-ES",
    "mjpeg": "JPEG", "jpeg": "JPEG",
    "h263":  "H263",
    "h263p": "H263-1998",
    "h261":  "H261",
}

# Known video encoding names (used for media-type classification from SDP)
_VIDEO_CODECS = set(CODECS.keys()) | {
    "MPV", "MP1S", "MP2T", "BMPEG", "THEORA", "AV1", "H264-SVC",
}
_AUDIO_CODECS = {
    "PCMU", "PCMA", "AMR", "AMR-WB", "G722", "G726", "G729", "OPUS",
    "SPEEX", "CN", "G723", "G728", "G711", "TELEPHONE-EVENT", "EVS",
    "RED", "G7221", "GSM", "MPA", "L16",
}

# RFC 3551 static payload types → (media, encoding-name)
STATIC_PT: Dict[int, Tuple[str, str]] = {
    0:  ("audio", "PCMU"),
    3:  ("audio", "GSM"),
    4:  ("audio", "G723"),
    8:  ("audio", "PCMA"),
    9:  ("audio", "G722"),
    14: ("audio", "MPA"),
    18: ("audio", "G729"),
    26: ("video", "JPEG"),
    31: ("video", "H261"),
    32: ("video", "MPV"),
    33: ("video", "MP2T"),
    34: ("video", "H263"),
}


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class PayloadInfo:
    media: str          # "video" | "audio"
    encoding_name: str  # e.g. "H264"
    clock_rate: int = 90000


@dataclass
class Stream:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload_type: int
    ssrc: str
    packets: int = 0
    # Resolved after SDP / heuristic analysis:
    media: str = "unknown"
    encoding_name: Optional[str] = None
    clock_rate: int = 90000


# ── tshark helpers ─────────────────────────────────────────────────────────────

def _tshark(*args: str) -> Optional[str]:
    try:
        r = subprocess.run(["tshark"] + list(args), capture_output=True, text=True)
        # tshark returns 1 when a display filter matches 0 packets — still valid
        return r.stdout if r.returncode in (0, 1) else None
    except FileNotFoundError:
        return None


def tshark_available() -> bool:
    return _tshark("--version") is not None


# ── SDP parsing ────────────────────────────────────────────────────────────────

def _classify_by_name_or_rate(encoding_name: str, clock_rate: int) -> str:
    """Classify 'video' / 'audio' / 'unknown' without needing the SDP m= section."""
    enc = encoding_name.upper()
    if enc in _VIDEO_CODECS:
        return "video"
    if enc in _AUDIO_CODECS:
        return "audio"
    # Clock-rate heuristic: video almost always uses 90 000 Hz
    if clock_rate == 90000:
        return "video"
    if clock_rate in (8000, 11025, 16000, 22050, 32000, 44100, 48000):
        return "audio"
    return "unknown"


def parse_sdp_mappings(pcap_file: str) -> Dict[int, PayloadInfo]:
    """
    Return {payload_type: PayloadInfo} from SDP a=rtpmap lines in the capture.
    Pre-seeded with RFC 3551 static payload types so callers always get results
    even when the capture has no SDP.
    """
    mappings: Dict[int, PayloadInfo] = {
        pt: PayloadInfo(media, enc)
        for pt, (media, enc) in STATIC_PT.items()
    }

    out = _tshark("-r", pcap_file, "-Y", "sdp", "-T", "fields", "-e", "sdp.rtpmap")
    if not out or not out.strip():
        return mappings

    # tshark may emit multiple a=rtpmap values per packet, comma-separated
    for line in out.splitlines():
        for entry in re.split(r"[,\n]+", line):
            entry = entry.strip()
            # Format: "<pt> <encoding-name>/<clock-rate>[/<channels>]"
            m = re.match(r"^(\d+)\s+([\w\-]+)/(\d+)", entry)
            if m:
                pt = int(m.group(1))
                enc = m.group(2).upper()
                rate = int(m.group(3))
                mappings[pt] = PayloadInfo(
                    media=_classify_by_name_or_rate(enc, rate),
                    encoding_name=enc,
                    clock_rate=rate,
                )

    return mappings


# ── Stream detection ───────────────────────────────────────────────────────────

def detect_streams(pcap_file: str) -> List[Stream]:
    """Return all unique RTP streams found in the capture via tshark."""
    out = _tshark(
        "-r", pcap_file,
        "-Y", "rtp",
        "-T", "fields",
        "-e", "ip.src",    "-e", "udp.srcport",
        "-e", "ip.dst",    "-e", "udp.dstport",
        "-e", "rtp.p_type", "-e", "rtp.ssrc",
    )
    if not out:
        return []

    index: Dict[tuple, Stream] = {}
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) < 5 or not all(cols[:5]):
            continue
        try:
            key = (cols[0], int(cols[1]), cols[2], int(cols[3]), int(cols[4]))
        except ValueError:
            continue
        if key not in index:
            index[key] = Stream(
                src_ip=cols[0], src_port=int(cols[1]),
                dst_ip=cols[2], dst_port=int(cols[3]),
                payload_type=int(cols[4]),
                ssrc=cols[5].strip() if len(cols) > 5 else "",
            )
        index[key].packets += 1

    return list(index.values())


def annotate(streams: List[Stream], sdp_map: Dict[int, PayloadInfo]) -> None:
    """Fill each stream's media / encoding_name / clock_rate from the SDP map."""
    for s in streams:
        info = sdp_map.get(s.payload_type)
        if info:
            s.media = info.media
            s.encoding_name = info.encoding_name
            s.clock_rate = info.clock_rate
        # else: leave as "unknown" — no SDP and not a static payload type


# ── Display ────────────────────────────────────────────────────────────────────

_HDR = (
    f"{'#':<4} {'Src IP':<16} {'Sport':<7} {'Dst IP':<16} {'Dport':<7}"
    f" {'PT':<6} {'Codec':<14} {'Media':<8} Packets"
)

def _stream_row(i: int, s: Stream) -> str:
    codec = s.encoding_name or "?"
    media = f"[{s.media}]"
    return (
        f"{i:<4} {s.src_ip:<16} {s.src_port:<7} {s.dst_ip:<16} {s.dst_port:<7}"
        f" {s.payload_type:<6} {codec:<14} {media:<8} {s.packets}"
    )

def print_table(streams: List[Stream], title: str = "") -> None:
    if title:
        print(f"\n[*] {title}")
    print(_HDR)
    print("-" * len(_HDR))
    for i, s in enumerate(streams):
        print(_stream_row(i, s))


# ── Pipeline builder ───────────────────────────────────────────────────────────

def build_pipeline(pcap_file: str, s: Stream, output_file: str) -> str:
    enc = s.encoding_name
    if not enc:
        raise ValueError(
            f"Codec unknown for payload type {s.payload_type}.\n"
            "  → Re-run with --codec h264 (or h265 / vp8 / vp9 / mpeg4 / mjpeg / h263)."
        )

    cfg = CODECS.get(enc.upper())
    if not cfg:
        raise ValueError(
            f"No GStreamer pipeline defined for codec '{enc}'.\n"
            f"  Supported: {', '.join(CODECS)}"
        )

    caps = (
        f"application/x-rtp,media=video"
        f",clock-rate={s.clock_rate}"
        f",encoding-name={enc.upper()}"
        f",payload={s.payload_type}"
    )

    parts = [
        f'filesrc location="{pcap_file}"',
        (
            f'pcapparse src-ip="{s.src_ip}" src-port={s.src_port}'
            f' dst-ip="{s.dst_ip}" dst-port={s.dst_port}'
        ),
        f'"{caps}"',
        cfg.depay,
    ]
    if cfg.parse:
        parts.append(cfg.parse)
    parts += [cfg.mux, f'filesink location="{output_file}"']

    return "gst-launch-1.0 -ve \\\n    " + " ! \\\n    ".join(parts)


# ── Extraction ─────────────────────────────────────────────────────────────────

def run_pipeline(
    pipeline: str,
    pkg_config_path: Optional[str],
    gst_plugin_path: Optional[str],
    lib_path: Optional[str],
) -> int:
    env = os.environ.copy()
    if pkg_config_path:
        env["PKG_CONFIG_PATH"] = f"{pkg_config_path}:{env.get('PKG_CONFIG_PATH', '')}"
    if gst_plugin_path:
        env["GST_PLUGIN_PATH"] = gst_plugin_path
    if lib_path:
        env["LD_LIBRARY_PATH"] = f"{lib_path}:{env.get('LD_LIBRARY_PATH', '')}"
    return subprocess.run(pipeline, shell=True, env=env).returncode


def extract(
    pcap_file: str,
    s: Stream,
    output_file: str,
    dry_run: bool,
    pkg_config_path: Optional[str],
    gst_plugin_path: Optional[str],
    lib_path: Optional[str],
) -> bool:
    try:
        pipeline = build_pipeline(pcap_file, s, output_file)
    except ValueError as e:
        print(f"[!] {e}")
        return False

    print(f"\n[*] Pipeline:\n{pipeline}\n")
    if dry_run:
        return True

    print(f"[*] Output → {output_file}")
    rc = run_pipeline(pipeline, pkg_config_path, gst_plugin_path, lib_path)
    if rc == 0:
        print(f"[+] Done: {output_file}")
        return True
    print(f"[!] GStreamer exited with code {rc}")
    return False


def _auto_output(pcap_file: str, s: Stream, tag: str = "") -> str:
    base = os.path.splitext(os.path.basename(pcap_file))[0]
    enc = (s.encoding_name or f"pt{s.payload_type}").lower().replace("-", "_")
    cfg = CODECS.get((s.encoding_name or "").upper())
    ext = cfg.ext if cfg else "bin"
    return f"{base}{tag}_{enc}.{ext}"


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="pcap_video_extractor.py",
        description=(
            "Detect and extract RTP video from any .pcap file.\n"
            "Parses SDP in the capture to identify codecs automatically."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES
  default          tshark detects streams; prompt if more than one video stream
  --list-streams   print every RTP stream (all media types) and exit
  --all            extract every video stream without prompting
  --stream N       extract stream N from the detected video-stream list

MANUAL OVERRIDE  (skips tshark entirely — useful when capture has no SDP or
                  tshark is not installed on the extraction machine)
  supply --src-ip / --src-port / --dst-ip / --dst-port / --payload-type / --codec

EXAMPLES
  # Fully automatic
  python3 pcap_video_extractor.py recording.pcap

  # See everything in the capture first
  python3 pcap_video_extractor.py recording.pcap --list-streams

  # Extract all video streams (e.g. both call legs) to separate files
  python3 pcap_video_extractor.py recording.pcap --all

  # Extract stream 1 from the detected list
  python3 pcap_video_extractor.py recording.pcap --stream 1

  # No SDP in the capture — specify codec explicitly
  python3 pcap_video_extractor.py recording.pcap --codec h264

  # Full manual override — no tshark required
  python3 pcap_video_extractor.py recording.pcap \\
      --src-ip 10.63.5.25 --src-port 16008 \\
      --dst-ip 10.44.139.11 --dst-port 11680 \\
      --payload-type 96 --codec h264 --output extracted.mp4

  # Custom GStreamer install paths (mirrors the reference bash script)
  python3 pcap_video_extractor.py recording.pcap \\
      --pkg-config-path /opt/k8-conference/INSTALL/lib64/pkgconfig \\
      --gst-plugin-path /opt/k8-conference/INSTALL/ \\
      --lib-path /opt/k8-conference/INSTALL/lib64

  # Print GStreamer command without running it
  python3 pcap_video_extractor.py recording.pcap --print-pipeline
""",
    )

    ap.add_argument("pcap_file", help="Input .pcap / .pcapng file")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--list-streams", "-l", action="store_true",
                      help="List all RTP streams and exit")
    mode.add_argument("--all", "-a", action="store_true",
                      help="Extract every video stream to separate files")
    mode.add_argument("--stream", "-s", type=int, metavar="N",
                      help="Extract stream N from the video-stream list")

    # Manual stream overrides
    ap.add_argument("--src-ip",       help="Source IP (manual override)")
    ap.add_argument("--src-port",     type=int, help="Source UDP port")
    ap.add_argument("--dst-ip",       help="Destination IP")
    ap.add_argument("--dst-port",     type=int, help="Destination UDP port")
    ap.add_argument("--payload-type", "-pt", type=int, help="RTP payload type number")
    ap.add_argument("--codec",        "-c",
                    choices=sorted(CODEC_ALIASES),
                    help="Force codec (e.g. h264, h265, vp8, vp9, mpeg4, mjpeg)")

    ap.add_argument("--output", "-o", metavar="FILE",
                    help="Output file (auto-named when omitted)")
    ap.add_argument("--print-pipeline", "-p", action="store_true",
                    help="Print GStreamer pipeline and exit without running")

    # GStreamer / library path overrides
    ap.add_argument("--pkg-config-path", metavar="PATH",
                    help="Prepend to PKG_CONFIG_PATH")
    ap.add_argument("--gst-plugin-path", metavar="PATH",
                    help="Set GST_PLUGIN_PATH")
    ap.add_argument("--lib-path",        metavar="PATH",
                    help="Prepend to LD_LIBRARY_PATH")

    args = ap.parse_args()

    if not os.path.isfile(args.pcap_file):
        sys.exit(f"[!] File not found: {args.pcap_file}")

    # Shared env kwargs forwarded to every extract() call
    env = dict(
        pkg_config_path=args.pkg_config_path,
        gst_plugin_path=args.gst_plugin_path,
        lib_path=args.lib_path,
    )

    # ── Manual mode: all four endpoints provided ───────────────────────────
    if all([args.src_ip, args.src_port, args.dst_ip, args.dst_port]):
        pt = args.payload_type or 96
        enc: Optional[str] = CODEC_ALIASES.get(args.codec or "", None) if args.codec else None
        # Fall back to static PT table if no --codec given
        if not enc and pt in STATIC_PT:
            _, enc = STATIC_PT[pt]

        s = Stream(
            src_ip=args.src_ip, src_port=args.src_port,
            dst_ip=args.dst_ip,  dst_port=args.dst_port,
            payload_type=pt, ssrc="",
            media="video", encoding_name=enc, clock_rate=90000,
        )
        out = args.output or _auto_output(args.pcap_file, s)
        ok = extract(args.pcap_file, s, out, args.print_pipeline, **env)
        sys.exit(0 if ok else 1)

    # ── Auto-detect mode ───────────────────────────────────────────────────
    if not tshark_available():
        sys.exit(
            "[!] tshark not found.\n"
            "    Install tshark (part of Wireshark) for auto-detection, or\n"
            "    provide all four of: --src-ip --src-port --dst-ip --dst-port"
        )

    print(f"[*] Scanning {args.pcap_file} …")
    sdp_map = parse_sdp_mappings(args.pcap_file)
    streams  = detect_streams(args.pcap_file)

    if not streams:
        sys.exit("[!] No RTP packets found in this capture.")

    annotate(streams, sdp_map)

    # --list-streams: show everything and exit
    if args.list_streams:
        print_table(streams, "All RTP streams")
        print(
            "\n  Tip: re-run with --stream N  (video streams only)"
            " or --all to extract all video."
        )
        sys.exit(0)

    # Apply --codec override to all streams (useful when no SDP is present)
    if args.codec:
        forced_enc = CODEC_ALIASES[args.codec]
        for s in streams:
            if s.media in ("video", "unknown"):
                s.encoding_name = forced_enc
                s.clock_rate    = CODECS[forced_enc].clock_rate
                s.media         = "video"

    # Identify video streams
    video = [s for s in streams if s.media == "video"]

    if not video:
        unknown = [s for s in streams if s.media == "unknown"]
        if unknown:
            print("[!] Could not classify media type — no SDP found in capture.")
            print_table(unknown, "Unclassified RTP streams (may contain video)")
            print(
                "\n  Tip: re-run with --codec h264  (or h265/vp8/…) to force extraction.\n"
                "       Use --stream N --codec <codec> to pick a specific stream."
            )
        else:
            print_table(streams, "All streams (no video detected)")
            print(
                "\n  All streams appear to be audio.\n"
                "  Use --stream N --codec <codec> to force extraction of any stream."
            )
        sys.exit(1)

    # Warn when codec is still unknown for some video streams
    unknown_codec = [s for s in video if not s.encoding_name]
    if unknown_codec and not args.codec:
        print(
            f"[!] {len(unknown_codec)} video stream(s) have an unknown codec "
            "(no SDP found). Use --codec to force.\n"
        )

    # ── Select targets ─────────────────────────────────────────────────────
    if args.all:
        targets: List[Tuple[int, Stream]] = list(enumerate(video))

    elif args.stream is not None:
        if args.stream >= len(video):
            print_table(video, "Available video streams")
            sys.exit(
                f"[!] --stream {args.stream} is out of range "
                f"(0–{len(video)-1})"
            )
        targets = [(args.stream, video[args.stream])]

    elif len(video) == 1:
        s = video[0]
        print(
            f"[*] Single video stream: "
            f"{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}  "
            f"PT={s.payload_type}  codec={s.encoding_name or '?'}"
        )
        targets = [(0, s)]

    else:
        print_table(video, "Multiple video streams — select one")
        while True:
            try:
                raw = input(f"\n  Stream number [0–{len(video)-1}]: ").strip()
                idx = int(raw)
                if 0 <= idx < len(video):
                    targets = [(idx, video[idx])]
                    break
                print(f"  Please enter a number between 0 and {len(video)-1}")
            except (ValueError, EOFError, KeyboardInterrupt):
                print()
                sys.exit(1)

    # ── Extract ────────────────────────────────────────────────────────────
    multi = len(targets) > 1
    ok_count = 0
    for idx, s in targets:
        if not s.encoding_name:
            print(
                f"\n[!] Skipping stream {idx} "
                f"({s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}): "
                "codec unknown. Add --codec <codec> to force."
            )
            continue

        out_file = (
            args.output
            if (not multi and args.output)
            else _auto_output(args.pcap_file, s, f"_stream{idx}" if multi else "")
        )
        if extract(args.pcap_file, s, out_file, args.print_pipeline, **env):
            ok_count += 1

    sys.exit(0 if ok_count == len(targets) else 1)


if __name__ == "__main__":
    main()
