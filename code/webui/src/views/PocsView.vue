<template>
  <div>
    <!-- Control Panel -->
    <div class="card" style="margin-bottom: 20px; padding: 20px">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px">
        <h2>{{ t('pocs.controlTitle') }}</h2>
        <div style="display: flex; gap: 20px; align-items: center">
          <div style="text-align: center"><div style="font-size: 1.4rem; font-weight: 800; color: var(--accent)">{{ runCount }}</div><div style="font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .5px">{{ t('pocs.running') }}</div></div>
          <div style="text-align: center"><div style="font-size: 1.4rem; font-weight: 800; color: var(--accent)">{{ maxConc }}</div><div style="font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .5px">{{ t('pocs.maxSlots') }}</div></div>
        </div>
      </div>
      <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap; font-size: 0.85rem">
        <label style="display: flex; align-items: center; gap: 6px; color: var(--muted); font-weight: 500">{{ t('pocs.concLabel') }} <input v-model.number="inputMaxConc" type="number" min="1" max="50" style="width: 70px; text-align: center" /></label>
        <label style="display: flex; align-items: center; gap: 6px; color: var(--muted); font-weight: 500">{{ t('pocs.maxfileLabel') }} <input v-model.number="inputMaxfile" type="number" min="10" max="100000" :disabled="runCount > 0" style="width: 80px; text-align: center" /></label>
        <button class="btn btn-ghost" @click="saveSettings">{{ t('pocs.apply') }}</button>
        <button class="btn btn-ghost" :disabled="runCount > 0" @click="doReload">{{ t('pocs.reload') }}</button>
      </div>
      <div style="font-size: 0.78rem; color: var(--muted); padding: 8px 12px; background: var(--hover-bg); border-radius: 6px; margin-top: 12px">
        Output → <code>files/waittocheck/{poc_id}/</code> | Max <b>{{ inputMaxfile }}</b> files per POC
      </div>
      <div v-if="reloadInfo" style="font-size: 0.78rem; padding: 8px 12px; border-radius: 6px; background: #fef3c7; color: #92400e; border: 1px solid #fde68a; margin-top: 10px">
        Last reload: {{ reloadInfo.last_reload_time }}{{ reloadInfo.reload_reason ? ' — ' + reloadInfo.reload_reason : '' }}
      </div>
    </div>

    <!-- POC List -->
    <div v-if="!pocData.length" class="empty">{{ loadError ? t('pocs.loadFail') : t('pocs.noPocs') }}</div>
    <div v-else class="poc-list">
      <template v-for="group in sortedGroups" :key="group.product">
        <div class="group-header">{{ group.product }}</div>
        <PocCard v-for="poc in sortedPocs(group)" :key="poc.id" :poc="poc" :run-status="runStatus" @start="onStart" @stop="onStop" @detail="showDetail" @edit="showEdit" />
      </template>
    </div>

    <!-- Modal -->
    <Teleport to="body">
      <div v-if="modalVisible" class="modal-overlay" @click.self="closeModal">
        <div class="modal" v-html="modalHtml"></div>
      </div>
    </Teleport>

    <!-- Toast -->
    <Teleport to="body">
      <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
    </Teleport>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '../composables/useApi'
import PocCard from '../components/PocCard.vue'

const { t } = useI18n()
const api = useApi()

const pocData = ref([])
const runStatus = ref({ pocs: [], running_count: 0 })
const loadError = ref(false)
const runCount = computed(() => runStatus.value.running_count || 0)
const maxConc = computed(() => runStatus.value.max_concurrent || 10)
const inputMaxConc = ref(10)
const inputMaxfile = ref(200)
const reloadInfo = ref(null)

const modalVisible = ref(false)
const modalHtml = ref('')
const toastMsg = ref('')
let toastTimer = null

const sortedGroups = computed(() => {
  const g = [...pocData.value]
  g.sort((a, b) => {
    const ap = (a.pocs || []).some(p => p.public) ? 1 : 0
    const bp = (b.pocs || []).some(p => p.public) ? 1 : 0
    return bp - ap
  })
  return g
})
function sortedPocs(group) {
  return [...(group.pocs || [])].sort((a, b) => (b.public ? 1 : 0) - (a.public ? 1 : 0))
}

function showToast(msg) {
  toastMsg.value = msg
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { toastMsg.value = '' }, 2000)
}
function closeModal() { modalVisible.value = false }

function fmtTime(s) {
  if (!s || s < 1) return '—'
  if (s < 60) return Math.round(s) + 's'
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's'
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'
}

async function loadPocs() {
  try {
    const d = await api.getPocsList()
    pocData.value = d.groups || []
    loadError.value = false
  } catch { loadError.value = true }
}
async function loadStatus() {
  try {
    const rs = await api.getPocsStatus()
    runStatus.value = rs
    inputMaxConc.value = rs.max_concurrent || 10
    inputMaxfile.value = rs.maxfile || 200
  } catch {}
}
async function loadReloadInfoFn() {
  try { reloadInfo.value = await api.getReloadInfo() } catch {}
}

async function onStart(id, name, force) {
  const mc = runStatus.value.max_concurrent || 10
  if (runCount.value >= mc) { alert(t('pocs.concLimitReached', { n: mc })); return }
  const body = { poc_id: id, poc_name: name }
  if (force) body.force = true
  const d = await api.startPoc(body)
  if (!d.ok) {
    if (d.completed) { if (confirm(t('pocs.restartConfirm'))) onStart(id, name, true) }
    else alert(d.error)
  } else loadStatus()
}
async function onStop(id) {
  const d = await api.stopPoc({ poc_id: id })
  if (!d.ok) alert(d.error)
  else loadStatus()
}

async function showDetail(id, name) {
  modalVisible.value = true
  modalHtml.value = '<h2>Loading...</h2>'
  try {
    const d = await api.getPocLog({ poc_id: id })
    const run = (runStatus.value.pocs || []).find(p => p.poc_id === id)
    const p = run?.progress || runStatus.value.all_progress?.[id] || {}
    const total = p.total_space || 'N/A'
    const done = p.total_generated || 0
    const pct = p.total_space ? (done / p.total_space * 100).toFixed(4) : 'N/A'
    const elapsed = run?.elapsed_secs || 0
    const status = d.is_running ? 'Running' : (run?.status || 'Idle')
    const log = (d.log || '(No log output yet)').replace(/</g, '&lt;')

    let pocMeta = null
    for (const g of pocData.value) { for (const pc of (g.pocs || [])) { if (pc.id === id) { pocMeta = pc; break } } if (pocMeta) break }

    let infoHtml = ''
    if (pocMeta) {
      const ot = pocMeta.output_type || 'unknown'
      const otBadge = ot === 'mnemonic' ? '<span class="badge badge-mnemonic">mnemonic</span>' : '<span class="badge badge-privkey">' + ot + '</span>'
      infoHtml = `<div style="margin-bottom:14px;padding:12px 14px;background:#eff6ff;border-radius:8px;border:1px solid #bfdbfe;font-size:0.85rem"><div style="font-weight:700;font-size:0.92rem;margin-bottom:8px;color:#1e40af">${t('pocs.pocInfo')}</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:6px"><div><b>Output:</b> ${otBadge}</div><div><b>Vendor:</b> ${pocMeta.vendor || '—'}</div><div><b>Entropy:</b> ${pocMeta.effective_entropy || '—'}</div><div><b>Space:</b> ${pocMeta.input_space || '—'}</div><div><b>Gen Speed:</b> ${pocMeta.generation_speed || '—'}</div><div><b>Fixed:</b> ${pocMeta.is_fixed ? '<span style="color:var(--green)">Yes</span>' : '<span style="color:var(--red)">No</span>'}</div></div>${pocMeta.root_cause ? '<div style="margin-top:6px"><b>Root Cause:</b> ' + pocMeta.root_cause + '</div>' : ''}${pocMeta.source_reference ? '<div style="margin-top:4px"><b>Ref:</b> <a href="' + pocMeta.source_reference + '" target="_blank" style="color:var(--accent)">' + pocMeta.source_reference + '</a></div>' : ''}</div>`
    }

    modalHtml.value = `<h2>${name || id}</h2>${infoHtml}<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:0.85rem;margin-bottom:14px;padding:12px;background:#f8fafc;border-radius:8px;border:1px solid var(--border)"><div><b>POC ID:</b> ${id}</div><div><b>Status:</b> ${status}</div><div><b>Progress:</b> ${pct}%</div><div><b>Generated:</b> ${typeof done === 'number' ? done.toLocaleString() : done}</div><div><b>Total Space:</b> ${typeof total === 'number' ? total.toLocaleString() : total}</div><div><b>Runtime:</b> ${fmtTime(elapsed)}</div><div><b>Batch:</b> ${p.batch_num || '—'}</div><div><b>Updated:</b> ${p.timestamp || '—'}</div></div><div style="font-size:0.85rem;font-weight:700;margin-bottom:8px">${t('pocs.logOutput')} ${d.is_running ? '<span class="badge badge-running">' + t('pocs.live') + '</span>' : ''}</div><pre style="background:#0f172a;color:#e2e8f0;padding:16px;border-radius:10px;font-size:0.78rem;line-height:1.5;overflow-x:auto;max-height:360px;overflow-y:auto;font-family:'JetBrains Mono',monospace">${log}</pre><div style="margin-top:16px;display:flex;justify-content:flex-end;gap:8px"><button class="btn btn-ghost" onclick="document.querySelector('.modal-overlay').click()">${t('pocs.close')}</button></div>`
  } catch (e) {
    modalHtml.value = '<h2>Error</h2><pre>' + e + '</pre>'
  }
}

function showEdit(id, name) {
  const p = runStatus.value.all_progress?.[id] || {}
  modalHtml.value = `<h2>${t('pocs.editTitle', { name: name || id })}</h2><div style="font-size:0.85rem;color:var(--muted);margin-bottom:14px">${t('pocs.editHint')}</div><div style="display:grid;gap:12px;font-size:0.92rem"><label style="display:grid;gap:4px">${t('pocs.currentIndex')}<input type="number" id="ep_index" value="${p.index || p.current_index || 0}" style="padding:8px 12px;border:1px solid var(--border);border-radius:6px"></label><label style="display:grid;gap:4px">${t('pocs.batchNumber')}<input type="number" id="ep_batch" value="${p.batch_num || 0}" style="padding:8px 12px;border:1px solid var(--border);border-radius:6px"></label><label style="display:grid;gap:4px">${t('pocs.totalGenerated')}<input type="number" id="ep_generated" value="${p.total_generated || 0}" style="padding:8px 12px;border:1px solid var(--border);border-radius:6px"></label><label style="display:grid;gap:4px">${t('pocs.totalSpace')}<input type="number" id="ep_space" value="${p.total_space || 0}" style="padding:8px 12px;border:1px solid var(--border);border-radius:6px"></label></div><div style="margin-top:18px;display:flex;justify-content:flex-end;gap:8px"><button class="btn btn-ghost" onclick="document.querySelector('.modal-overlay').click()">${t('pocs.cancel')}</button><button class="btn btn-success" id="ep_save_btn">${t('pocs.save')}</button></div>`
  modalVisible.value = true
  // Use event delegation for save
  setTimeout(() => {
    const btn = document.getElementById('ep_save_btn')
    if (btn) btn.onclick = () => doSaveProgress(id)
  }, 50)
}

async function doSaveProgress(id) {
  const data = {
    poc_id: id,
    current_index: parseInt(document.getElementById('ep_index')?.value) || 0,
    batch_num: parseInt(document.getElementById('ep_batch')?.value) || 0,
    total_generated: parseInt(document.getElementById('ep_generated')?.value) || 0,
    total_space: parseInt(document.getElementById('ep_space')?.value) || 0,
  }
  const d = await api.editPocProgress(data)
  if (d.ok) { closeModal(); loadStatus(); showToast(t('pocs.progressUpdated')) }
  else alert(d.error)
}

async function saveSettings() {
  const d = await api.savePocSettings({ max_concurrent: inputMaxConc.value, maxfile: inputMaxfile.value })
  if (d.ok) { loadStatus(); showToast(t('pocs.settingsSaved')) }
  else alert(d.error || 'Save failed')
}

async function doReload() {
  if (runCount.value > 0) { alert(t('pocs.stopAllFirst')); return }
  const d = await api.reloadPocs()
  if (d.ok) { await loadPocs(); loadReloadInfoFn(); showToast(t('pocs.reloadSuccess')) }
  else alert(d.error)
}

let statusTimer = null, reloadTimer = null
onMounted(() => {
  loadPocs()
  loadStatus()
  loadReloadInfoFn()
  statusTimer = setInterval(loadStatus, 3000)
  reloadTimer = setInterval(loadReloadInfoFn, 5000)
})
onUnmounted(() => {
  clearInterval(statusTimer)
  clearInterval(reloadTimer)
  clearTimeout(toastTimer)
})
</script>

<style scoped>
.poc-list { display: flex; flex-direction: column; gap: 10px; }
.group-header { font-size: 0.85rem; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: .5px; padding: 6px 0; border-bottom: 2px solid var(--accent); margin-bottom: 8px; margin-top: 6px; }
</style>
