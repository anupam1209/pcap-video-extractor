#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# extract_video.sh  —  manual GStreamer pipeline template
#
# Edit the variables in the CONFIG section and uncomment the codec block
# that matches your stream.  Run: bash extract_video.sh
#
# For full auto-detection use the Python script:
#   python3 pcap_video_extractor.py recording.pcap
# ─────────────────────────────────────────────────────────────────────────────

# ── CONFIG ────────────────────────────────────────────────────────────────────
PCAP="/path/to/capture.pcap"
OUTPUT="/path/to/output"     # extension added automatically per codec below

SRC_IP="10.63.5.25"
SRC_PORT=16008
DST_IP="10.44.139.11"
DST_PORT=11680

PAYLOAD_TYPE=96              # check with: python3 pcap_video_extractor.py $PCAP --list-streams

# ── Optional: custom GStreamer install (comment out if using system GStreamer)
export PKG_CONFIG_PATH=/opt/k8-conference/INSTALL/lib64/pkgconfig:/opt/k8-conference/INSTALL/lib/pkgconfig:/usr/lib64/pkgconfig/
export GST_PLUGIN_PATH=/opt/k8-conference/INSTALL/
export LD_LIBRARY_PATH=/opt/k8-conference/INSTALL/lib64:/opt/k8-conference/INSTALL/lib


# ── CODEC PIPELINES  (uncomment exactly ONE block) ────────────────────────────

# ── H.264  →  .mp4
gst-launch-1.0 -ve \
    filesrc location="$PCAP" ! \
    pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
    "application/x-rtp,media=video,clock-rate=90000,encoding-name=H264,payload=$PAYLOAD_TYPE" ! \
    rtph264depay ! h264parse ! mp4mux ! \
    filesink location="${OUTPUT}.mp4"

# ── H.265 / HEVC  →  .mp4
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=H265,payload=$PAYLOAD_TYPE" ! \
#     rtph265depay ! h265parse ! mp4mux ! \
#     filesink location="${OUTPUT}.mp4"

# ── VP8  →  .webm
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=VP8,payload=$PAYLOAD_TYPE" ! \
#     rtpvp8depay ! webmmux ! \
#     filesink location="${OUTPUT}.webm"

# ── VP9  →  .webm
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=VP9,payload=$PAYLOAD_TYPE" ! \
#     rtpvp9depay ! webmmux ! \
#     filesink location="${OUTPUT}.webm"

# ── MPEG-4 Visual  →  .mp4
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=MP4V-ES,payload=$PAYLOAD_TYPE" ! \
#     rtpmp4vdepay ! mpeg4videoparse ! mp4mux ! \
#     filesink location="${OUTPUT}.mp4"

# ── Motion JPEG  →  .avi   (static PT=26)
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=JPEG,payload=26" ! \
#     rtpjpegdepay ! avimux ! \
#     filesink location="${OUTPUT}.avi"

# ── H.263  →  .avi   (static PT=34)
# gst-launch-1.0 -ve \
#     filesrc location="$PCAP" ! \
#     pcapparse src-ip="$SRC_IP" src-port=$SRC_PORT dst-ip="$DST_IP" dst-port=$DST_PORT ! \
#     "application/x-rtp,media=video,clock-rate=90000,encoding-name=H263,payload=34" ! \
#     rtph263depay ! avimux ! \
#     filesink location="${OUTPUT}.avi"

echo "Done."
