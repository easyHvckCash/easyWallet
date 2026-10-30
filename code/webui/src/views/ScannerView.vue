<template>
  <div>
    <!-- System Bar -->
    <div class="sys-bar">
      <span class="sys-item"><span class="sys-label">{{ t('scanner.master') }}</span><span class="sys-val">{{ sysinfo.hostname || '-' }}</span></span>
      <span class="sys-item"><span class="sys-label">CPU:</span><span class="sys-val">{{ sysinfo.cpu_name || '-' }}</span></span>
      <span class="sys-item">
        <span class="sys-val">{{ cpuPct }}%</span>
        <span class="meter"><span class="meter-fill" :class="meterClass(cpuPct)" :style="{ width: cpuPct + '%' }"></span></span>
      </span>
      <span class="sys-item">
        <span class="sys-label">RAM:</span>
        <span class="sys-val">{{ sysinfo.used_memory_mb || 0 }}/{{ sysinfo.total_memory_mb || 0 }} MB</span>
        <span class="meter"><span class="meter-fill" :class="meterClass(memPct)" :style="{ width: memPct + '%' }"></span></span>
      </span>
      <span class="sys-item"><span class="sys-label">{{ t('scanner.uptime') }}</span><span class="sys-val">{{ uptimeStr }}</span></span>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
      <button class="btn btn-success" :disabled="dispatching" @click="doStart">{{ t('scanner.startBtn') }}</button>
      <button class="btn btn-danger" :disabled="!dispatching" @click="doStop">{{ t('scanner.stopBtn') }}</button>
      <button class="btn btn-primary" @click="doExport">{{ t('scanner.exportBtn') }}</button>
      <span class="status-pill" :class="dispatching ? 'status-running' : 'status-idle'">
        {{ dispatching ? t('scanner.dispatching') : t('scanner.idle') }}
      </span>
      <div class="divider"></div>
      <span style="font-size: 0.85rem; color: var(--muted)">{{ t('scanner.queueLimit') }}</span>
      <input v-model.number="queueLimit" type="text" inputmode="numeric" style="width: 70px; text-align: center" />
      <button class="btn btn-primary btn-sm" @click="applyQueueLimit">{{ t('scanner.applyBtn') }}</button>
      <div class="divider"></div>
      <span style="font-size: 0.85rem; color: var(--muted)">{{ t('scanner.toolbarHint') }}</span>
    </div>

    <!-- Stat Cards -->
    <div class="stat-grid" style="margin-bottom: 16px">
      <div class="card stat-card"><div class="val">{{ status.speed_mps || '0' }}</div><div class="lbl">{{ t('scanner.speed') }}</div></div>
      <div class="card stat-card"><div class="val">{{ fmt(status.total_mnemonics) }}</div><div class="lbl">{{ t('scanner.scanned') }}</div></div>
      <div class="card stat-card"><div class="val">{{ status.total_hits || 0 }}</div><div class="lbl">{{ t('scanner.hits') }}</div></div>
      <div class="card stat-card"><div class="val">{{ onlineCount }}</div><div class="lbl">{{ t('scanner.nodesOnline') }}</div></div>
      <div class="card stat-card"><div class="val">{{ status.pending_tasks || 0 }}</div><div class="lbl">{{ t('scanner.pending') }}</div></div>
      <div class="card stat-card"><div class="val">{{ fmt(cluster.completed_tasks) }}</div><div class="lbl">{{ t('scanner.completed') }}</div></div>
    </div>

    <!-- Nodes Table -->
    <div class="section-title">{{ t('scanner.nodes') }}</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Node</th><th>Hostname</th><th>CPU</th><th>GPU</th><th>GPU%</th>
            <th>VRAM</th><th>Temp</th><th>Speed</th><th>Scanned</th><th>Hits</th>
            <th>CPU%</th><th>RAM</th><th>Status</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!nodes.length">
            <td colspan="14" class="empty">{{ t('scanner.waiting') }}</td>
          </tr>
          <tr v-for="n in nodes" :key="n.node_id">
            <td class="mono" style="font-size: 0.78rem" :title="n.node_id">{{ n.node_id.substring(0, 8) }}</td>
            <td>{{ n.hostname || '-' }}</td>
            <td style="font-size: 0.78rem">{{ n.cpu_name || '-' }}</td>
            <td style="font-size: 0.78rem">{{ n.gpu_name || '-' }}</td>
            <td>{{ n.gpu_util != null ? Math.round(n.gpu_util) + '%' : '-' }}</td>
            <td style="font-size: 0.78rem">{{ n.gpu_mem_total_mb ? (n.gpu_mem_used_mb || 0) + '/' + n.gpu_mem_total_mb + 'MB' : '-' }}</td>
            <td>{{ n.gpu_temp_c ? n.gpu_temp_c + '°C' : '-' }}</td>
            <td style="font-weight: 600">{{ n.benchmark_speed ? n.benchmark_speed.toFixed(0) : (n.speed ? n.speed.toFixed(0) : '-') }}</td>
            <td>{{ fmt(n.total_scanned) }}</td>
            <td>{{ n.total_hits || 0 }}</td>
            <td>{{ n.cpu_usage != null ? Math.round(n.cpu_usage) + '%' : '-' }}</td>
            <td>{{ n.memory_usage != null ? Math.round(n.memory_usage) + '%' : '-' }}</td>
            <td :class="n.status === 'online' ? 'st-on' : 'st-off'">
              {{ n.status }} {{ agoStr(n.last_heartbeat_secs_ago) }}
            </td>
            <td>
              <div class="actions-cell">
                <button v-if="n.enabled !== false" class="btn btn-sm btn-danger" @click="doToggle(n.node_id, false)">
                  {{ t('scanner.pause') }}
                </button>
                <button v-else class="btn btn-sm btn-success" @click="doToggle(n.node_id, true)">
                  {{ t('scanner.start') }}
                </button>

                <button v-if="modeSwitching[n.node_id]" class="btn btn-sm btn-ghost" disabled>{{ t('scanner.switching') }}</button>
                <button v-else-if="n.gpu_available && (n.compute_mode || 'cpu') === 'cpu'" class="btn btn-sm" :class="n.enabled !== false ? 'btn-ghost' : 'btn-gpu'" :disabled="n.enabled !== false" :title="n.enabled !== false ? t('scanner.pauseFirst') : ''" @click="doSwitch(n.node_id, 'gpu')">
                  {{ t('scanner.switchGpu') }}
                </button>
                <button v-else-if="n.gpu_available && (n.compute_mode || 'cpu') === 'gpu'" class="btn btn-sm" :class="n.enabled !== false ? 'btn-ghost' : 'btn-cpu'" :disabled="n.enabled !== false" :title="n.enabled !== false ? t('scanner.pauseFirst') : ''" @click="doSwitch(n.node_id, 'cpu')">
                  {{ t('scanner.switchCpu') }}
                </button>
                <button v-else class="btn btn-sm btn-ghost" disabled :title="n.gpu_error || 'No GPU'">{{ t('scanner.cpuOnly') }}</button>

                <input v-model.number="nodeLimits[n.node_id]" type="text" inputmode="numeric" style="width: 40px; text-align: center; font-size: 0.72rem" :title="t('scanner.taskLimit')" />
                <button class="btn btn-sm btn-primary" style="padding: 2px 8px" @click="applyNodeLimit(n.node_id)">{{ t('scanner.applyBtn') }}</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '../composables/useApi'

const { t } = useI18n()
const api = useApi()

const status = ref({})
const sysinfo = ref({})
const cluster = ref({})
const nodes = ref([])
const dispatching = ref(false)
const queueLimit = ref(500)
const modeSwitching = reactive({})
const nodeLimits = reactive({})

const cpuPct = computed(() => Math.round(sysinfo.value.cpu_usage || 0))
const memPct = computed(() => {
  const total = sysinfo.value.total_memory_mb || 0
  return total > 0 ? Math.round((sysinfo.value.used_memory_mb || 0) / total * 100) : 0
})
const uptimeStr = computed(() => {
  const s = sysinfo.value.uptime_secs
  if (!s) return '-'
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
  return h + 'h ' + m + 'm'
})
const onlineCount = computed(() => nodes.value.filter(n => n.status === 'online').length)

function meterClass(pct) {
  return pct > 85 ? 'fill-danger' : pct > 60 ? 'fill-warn' : 'fill-ok'
}
function fmt(n) {
  n = Number(n || 0)
  return n >= 1e6 ? (n / 1e6).toFixed(2) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(n)
}
function agoStr(secs) {
  if (secs == null) return '?'
  return secs < 60 ? Math.round(secs) + 's' : Math.round(secs / 60) + 'm'
}

let timer = null
async function refresh() {
  try {
    const d = await api.getStatus()
    status.value = d
    dispatching.value = d.dispatching || false
    if (d.max_queue_size != null) queueLimit.value = d.max_queue_size
  } catch {}
  try { sysinfo.value = await api.getSysinfo() } catch {}
  try {
    const c = await api.getClusterStatus()
    cluster.value = c
    nodes.value = c.nodes || []
    for (const n of nodes.value) {
      if (!(n.node_id in nodeLimits)) nodeLimits[n.node_id] = n.task_limit || 0
    }
  } catch {}
}

async function doStart() { await api.startDispatch(); refresh() }
async function doStop() { await api.stopDispatch(); refresh() }
async function doExport() {
  const d = await api.exportJson()
  alert(d.ok ? t('scanner.exportSuccess') : t('scanner.exportFail') + ': ' + (d.error || ''))
}
async function applyQueueLimit() {
  const v = parseInt(queueLimit.value)
  if (isNaN(v) || v < 0) { alert(t('scanner.invalidValue')); return }
  const r = await api.setQueueLimit(v)
  if (r.ok) alert(t('scanner.setSuccess', { v }))
  else alert('Failed: ' + (r.error || ''))
}
async function doToggle(id, en) { await api.toggleNode(id, en); refresh() }
async function doSwitch(id, mode) {
  if (modeSwitching[id]) return
  modeSwitching[id] = true
  const r = await api.switchNodeMode(id, mode)
  if (!r.ok) { alert(r.error || 'unknown'); modeSwitching[id] = false; return }
  setTimeout(() => { modeSwitching[id] = false; refresh() }, 5000)
}
async function applyNodeLimit(nodeId) {
  const v = parseInt(nodeLimits[nodeId])
  if (isNaN(v) || v < 0) { alert(t('scanner.invalidValue')); return }
  const r = await api.setNodeLimit(nodeId, v)
  if (r.ok) { alert(t('scanner.nodeSetSuccess', { v })); refresh() }
  else alert('Failed: ' + (r.error || ''))
}

onMounted(() => { refresh(); timer = setInterval(refresh, 3000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.st-on  { color: var(--green); font-weight: 600; }
.st-off { color: var(--red); font-weight: 600; }
.mono   { font-family: 'JetBrains Mono', monospace; }
.actions-cell { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }
.btn-gpu { background: #dbeafe; color: #2563eb; border: 1px solid #bfdbfe; }
.btn-cpu { background: #f3e8ff; color: #7c3aed; border: 1px solid #e9d5ff; }
</style>
