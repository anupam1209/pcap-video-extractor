'use strict';

// ── Supported codecs (must match backend CODECS dict) ─────────────────────────
const CODECS = [
  { value: 'H264',      label: 'H.264 (AVC)',       ext: 'mp4'  },
  { value: 'H265',      label: 'H.265 (HEVC)',       ext: 'mp4'  },
  { value: 'VP8',       label: 'VP8',                ext: 'webm' },
  { value: 'VP9',       label: 'VP9',                ext: 'webm' },
  { value: 'MP4V-ES',   label: 'MPEG-4 Visual',      ext: 'mp4'  },
  { value: 'JPEG',      label: 'Motion JPEG',        ext: 'avi'  },
  { value: 'H263',      label: 'H.263',              ext: 'avi'  },
  { value: 'H263-1998', label: 'H.263+ (1998)',      ext: 'avi'  },
  { value: 'H261',      label: 'H.261',              ext: 'avi'  },
];

// ── App state ──────────────────────────────────────────────────────────────────
const state = {
  fileId:        null,
  filename:      null,
  fileSize:      0,
  streams:       [],
  jobId:         null,
  pollTimer:     null,
  maxUploadMB:   500,    // updated from /api/health on boot
};

// ── DOM shortcuts ──────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Boot ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initDropZone();
  checkDeps();
});

// ── Dependency check ───────────────────────────────────────────────────────────
async function checkDeps() {
  try {
    const r = await fetch('/api/health');
    const h = await r.json();

    if (h.max_upload_mb) {
      state.maxUploadMB = h.max_upload_mb;
      const hint = $('drop-hint');
      if (hint) hint.textContent = `.pcap and .pcapng · max ${h.max_upload_mb} MB`;
    }

    const missing = [];
    if (!h.tshark)    missing.push('<strong>tshark</strong> (Wireshark CLI)');
    if (!h.gstreamer) missing.push('<strong>gst-launch-1.0</strong> (GStreamer)');
    if (missing.length) {
      $('dep-warning-msg').innerHTML =
        `Missing server tools: ${missing.join(', ')}. ` +
        `The server administrator needs to install them.`;
      $('dep-warning').style.display = 'block';
    }
  } catch (_) { /* server not ready yet */ }
}

// ── Upload / drop-zone ─────────────────────────────────────────────────────────
function initDropZone() {
  const zone  = $('drop-zone');
  const input = $('file-input');

  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });
  zone.addEventListener('click',  () => input.click());
  zone.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  input.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });
}

function handleFile(file) {
  if (!/\.(pcap|pcapng)$/i.test(file.name)) {
    showAlert('danger', 'Only .pcap and .pcapng files are supported.');
    return;
  }
  if (file.size > state.maxUploadMB * 1024 * 1024) {
    showAlert('danger', `File is ${fmtBytes(file.size)} — exceeds the ${state.maxUploadMB} MB server limit.`);
    return;
  }
  uploadFile(file);
}

async function uploadFile(file) {
  showSection('loading');
  $('loading-msg').textContent = `Uploading ${file.name}…`;
  $('loading-sub').textContent = `${fmtBytes(file.size)} · analysing RTP streams with tshark`;

  const fd = new FormData();
  fd.append('file', file);

  try {
    const r = await fetch('/api/upload', { method: 'POST', body: fd });
    if (!r.ok) {
      const e = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(e.detail || 'Upload failed');
    }
    const data = await r.json();

    state.fileId   = data.file_id;
    state.filename = data.filename;
    state.fileSize = data.size;
    state.streams  = data.streams;

    renderSummaryCards(data.streams);
    renderStreamsTable(data.streams);
    showSection('streams');

  } catch (err) {
    showSection('upload');
    showAlert('danger', `Upload / analysis failed: ${err.message}`);
  }
}

// ── Summary stat cards ─────────────────────────────────────────────────────────
function renderSummaryCards(streams) {
  const counts = { video: 0, audio: 0, unknown: 0 };
  streams.forEach(s => { counts[s.media] = (counts[s.media] || 0) + 1; });

  const icons = { video: 'fa-film', audio: 'fa-music', unknown: 'fa-question-circle' };
  const labels = { video: 'Video Streams', audio: 'Audio Streams', unknown: 'Unknown' };

  $('bar-filename').textContent = state.filename;
  $('bar-size').textContent = fmtBytes(state.fileSize);

  const cont = $('summary-cards');
  cont.innerHTML = ['video', 'audio', 'unknown'].map(k => `
    <div class="col-sm-4">
      <div class="stat-card ${k}">
        <div class="stat-num">${counts[k] || 0}</div>
        <div class="stat-label"><i class="fa-solid ${icons[k]} me-1"></i>${labels[k]}</div>
      </div>
    </div>
  `).join('');
}

// ── Streams table ──────────────────────────────────────────────────────────────
function renderStreamsTable(streams) {
  const tbody = $('streams-tbody');

  const codecOptions = CODECS.map(c =>
    `<option value="${c.value}">${c.value} — ${c.label}</option>`
  ).join('');

  tbody.innerHTML = streams.map((s, i) => {
    const mediaBadgeClass = s.media === 'video' ? 'badge-video'
                          : s.media === 'audio' ? 'badge-audio' : 'badge-unknown';
    const isVideo   = s.media === 'video';
    const checked   = isVideo ? 'checked' : '';
    const knownCodec = CODECS.find(c => c.value === s.encoding_name);
    const codecSel = `
      <select class="form-select form-select-sm codec-select" id="codec-${i}"
              data-idx="${i}" onchange="onCodecChange(${i})">
        <option value="" ${!s.encoding_name ? 'selected' : ''}>— Unknown —</option>
        ${CODECS.map(c =>
          `<option value="${c.value}" ${s.encoding_name === c.value ? 'selected' : ''}>
             ${c.value} — ${c.label}
           </option>`
        ).join('')}
      </select>`;

    return `
      <tr class="stream-row ${isVideo ? 'selected-row' : ''}" id="row-${i}">
        <td class="text-center">
          <input type="checkbox" class="checkbox-lg stream-check" data-idx="${i}"
                 id="chk-${i}" ${checked} onchange="onCheckChange(${i})" />
        </td>
        <td class="text-muted small">${i}</td>
        <td>
          <span class="fw-semibold">${s.src_ip}</span>
          <span class="text-muted small">:${s.src_port}</span>
        </td>
        <td>
          <span class="fw-semibold">${s.dst_ip}</span>
          <span class="text-muted small">:${s.dst_port}</span>
        </td>
        <td>
          <input type="number" class="form-control form-control-sm" id="pt-${i}"
                 value="${s.payload_type}" style="width:70px" min="0" max="127" />
        </td>
        <td>${codecSel}</td>
        <td>
          <input type="number" class="form-control form-control-sm" id="cr-${i}"
                 value="${s.clock_rate}" style="width:90px" />
        </td>
        <td>
          <span class="badge rounded-pill ${mediaBadgeClass}">
            ${s.media}
          </span>
        </td>
        <td class="text-muted small">${s.packets.toLocaleString()}</td>
        <td class="text-muted small font-monospace" style="font-size:.7rem">${s.ssrc || '—'}</td>
      </tr>`;
  }).join('');

  updateSelectionCount();
}

function onCheckChange(idx) {
  const row = $(`row-${idx}`);
  if ($(`chk-${idx}`).checked) {
    row.classList.add('selected-row');
  } else {
    row.classList.remove('selected-row');
  }
  updateSelectionCount();
}

function onCodecChange(idx) {
  // Auto-tick the checkbox when user picks a codec
  const chk = $(`chk-${idx}`);
  if ($(`codec-${idx}`).value) chk.checked = true;
  onCheckChange(idx);
}

function selectAllVideo() {
  state.streams.forEach((s, i) => {
    const chk = $(`chk-${i}`);
    chk.checked = (s.media === 'video');
    onCheckChange(i);
  });
}

function deselectAll() {
  state.streams.forEach((_, i) => {
    $(`chk-${i}`).checked = false;
    onCheckChange(i);
  });
}

function updateSelectionCount() {
  const n = document.querySelectorAll('.stream-check:checked').length;
  $('selection-count').textContent = `${n} stream${n !== 1 ? 's' : ''} selected`;
  $('btn-extract').disabled = (n === 0);
}

function getSelectedStreams() {
  const result = [];
  state.streams.forEach((s, i) => {
    if (!$(`chk-${i}`).checked) return;
    const enc = $(`codec-${i}`).value;
    if (!enc) { showAlert('warning', `Stream ${i}: please select a codec before extracting.`); return; }
    result.push({
      src_ip:        s.src_ip,
      src_port:      s.src_port,
      dst_ip:        s.dst_ip,
      dst_port:      s.dst_port,
      payload_type:  parseInt($(`pt-${i}`).value, 10),
      encoding_name: enc,
      clock_rate:    parseInt($(`cr-${i}`).value, 10) || 90000,
    });
  });
  return result;
}

// ── Extraction ─────────────────────────────────────────────────────────────────
async function startExtraction() {
  clearAlerts();
  const selected = getSelectedStreams();
  if (!selected.length) return;

  const payload = {
    file_id: state.fileId,
    streams: selected,
    pkg_config_path: $('pkg-config-path').value.trim() || null,
    gst_plugin_path: $('gst-plugin-path').value.trim() || null,
    lib_path:        $('lib-path').value.trim()        || null,
  };

  try {
    const r = await fetch('/api/extract', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({ detail: r.statusText }));
      throw new Error(e.detail || 'Failed to start extraction');
    }
    const data = await r.json();
    state.jobId = data.job_id;

    renderProgressSection(selected.length);
    showSection('progress');
    state.pollTimer = setInterval(pollJob, 1500);

  } catch (err) {
    showAlert('danger', `Extraction error: ${err.message}`);
  }
}

// ── Progress polling ───────────────────────────────────────────────────────────
function renderProgressSection(total) {
  $('prog-text').textContent = `0 / ${total}`;
  $('prog-bar').style.width = '0%';
  $('stream-progress-list').innerHTML = '';
}

async function pollJob() {
  try {
    const r = await fetch(`/api/job/${state.jobId}`);
    if (!r.ok) return;
    const job = await r.json();

    const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
    $('prog-text').textContent = `${job.done} / ${job.total}`;
    $('prog-bar').style.width = `${pct}%`;

    // Per-stream status rows
    const list = $('stream-progress-list');
    list.innerHTML = job.streams.map(s => {
      const icon = {
        pending:   `<i class="fa-regular fa-clock text-secondary"></i>`,
        running:   `<i class="fa-solid fa-spinner fa-spin text-primary"></i>`,
        completed: `<i class="fa-solid fa-circle-check text-success"></i>`,
        failed:    `<i class="fa-solid fa-circle-xmark text-danger"></i>`,
      }[s.status] || '';

      const logBtn = s.status === 'failed' && s.log
        ? `<button class="btn btn-link btn-sm p-0 ms-2 text-danger"
                   onclick="showLog(${s.index})">view log</button>`
        : '';

      return `
        <div class="stream-prog-item">
          <span class="stream-prog-icon">${icon}</span>
          <span class="prog-label">${s.src} → ${s.dst} <span class="text-muted">(${s.codec})</span></span>
          <span class="prog-status ${s.status}">${s.status}${logBtn}</span>
        </div>`;
    }).join('');

    if (job.status === 'completed') {
      clearInterval(state.pollTimer);
      renderDownloads(job);
      setTimeout(() => showSection('downloads'), 600);
    }
  } catch (_) { /* keep polling */ }
}

function showLog(streamIdx) {
  fetch(`/api/job/${state.jobId}`)
    .then(r => r.json())
    .then(job => {
      const s = job.streams[streamIdx];
      alert(`GStreamer log for stream ${streamIdx}:\n\n${s.log || '(empty)'}`);
    });
}

// ── Downloads ──────────────────────────────────────────────────────────────────
function renderDownloads(job) {
  const cont = $('download-list');
  const extIcon = { mp4: 'fa-file-video', webm: 'fa-file-video', avi: 'fa-file-video' };

  const successItems = job.outputs.map(o => {
    const ext = o.filename.split('.').pop();
    const icon = extIcon[ext] || 'fa-file';
    return `
      <div class="download-item">
        <div class="download-icon"><i class="fa-solid ${icon}"></i></div>
        <div class="download-info">
          <div class="download-name">${o.filename}</div>
          <div class="download-meta">${fmtBytes(o.size)} · ${ext.toUpperCase()}</div>
        </div>
        <a href="/api/download/${o.job_id}/${encodeURIComponent(o.filename)}"
           class="btn btn-primary" download="${o.filename}">
          <i class="fa-solid fa-download me-1"></i>Download
        </a>
      </div>`;
  }).join('');

  const errorItems = job.errors.map(e => `
    <div class="download-failed">
      <i class="fa-solid fa-triangle-exclamation me-2"></i>
      Stream ${e.stream_index} failed: ${e.message}
    </div>`).join('');

  cont.innerHTML = successItems + errorItems ||
    '<p class="text-muted text-center py-3">No files were extracted.</p>';
}

// ── Navigation helpers ─────────────────────────────────────────────────────────
function backToStreams() {
  clearInterval(state.pollTimer);
  showSection('streams');
}

function resetApp() {
  clearInterval(state.pollTimer);
  // Clean up uploaded file on server (fire-and-forget)
  if (state.fileId) fetch(`/api/cleanup/${state.fileId}`, { method: 'DELETE' }).catch(() => {});

  state.fileId = null;
  state.filename = null;
  state.fileSize = 0;
  state.streams = [];
  state.jobId = null;
  $('file-input').value = '';
  clearAlerts();
  showSection('upload');
}

// ── UI helpers ─────────────────────────────────────────────────────────────────
const SECTIONS = ['upload', 'loading', 'streams', 'progress', 'downloads'];

function showSection(name) {
  SECTIONS.forEach(s => {
    const el = $(`sec-${s}`);
    if (el) el.style.display = (s === name) ? '' : 'none';
  });
}

function showAlert(type, msg) {
  const a = $('alert-area');
  const id = `alert-${Date.now()}`;
  a.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="alert alert-${type} alert-dismissible fade show" role="alert">
      ${msg}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`);
  // Auto-dismiss info/success after 6 s
  if (type === 'success' || type === 'info') {
    setTimeout(() => document.getElementById(id)?.remove(), 6000);
  }
}

function clearAlerts() {
  $('alert-area').innerHTML = '';
}

function fmtBytes(b) {
  if (b < 1024)       return `${b} B`;
  if (b < 1048576)    return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}
