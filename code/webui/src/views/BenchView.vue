<template>
  <div>
    <!-- Toolbar: Node selection + Mode switch -->
    <div class="toolbar">
      <div style="display: flex; align-items: center; gap: 12px; flex: 1">
        <span style="font-size: 0.85rem; color: var(--muted); font-weight: 500">{{ t('bench.targetNode') }}</span>
        <select v-model="selectedNodeId" @change="onNodeSelect" style="min-width: 200px">
          <option value="">{{ t('bench.selectNode') }}</option>
          <option v-for="n in nodesData" :key="n.node_id" :value="n.node_id" :disabled="n.enabled">
            {{ n.hostname }} ({{ n.node_id.substring(0, 8) }}) - {{ n.gpu_name || 'CPU-only' }}{{ n.enabled ? ' [RUNNING]' : '' }}
          </option>
        </select>
        <span style="font-size: 0.78rem" :style="{ color: hintColor }">{{ hintText }}</span>
      </div>
      <div class="mode-switch">
        <button :class="{ active: benchMode === 'gpu' }" :disabled="!canGpu" @click="setMode('gpu')">CUDA</button>
        <button :class="{ active: benchMode === 'cpu' }" :disabled="!selectedNode" @click="setMode('cpu')">CPU</button>
      </div>
      <span style="font-size: 0.78rem; color: var(--muted)">{{ selectedNode?.gpu_name ? 'GPU: ' + selectedNode.gpu_name : '' }}</span>
    </div>

    <!-- Benchmark Input -->
    <div class="card" style="margin-bottom: 16px">
      <h2 style="color: var(--muted); font-weight: 500; margin-bottom: 12px">{{ t('bench.inputTitle') }}</h2>
      <div style="display: flex; gap: 16px; margin-bottom: 10px; align-items: center">
        <span style="font-size: 0.85rem; color: var(--muted); font-weight: 500">{{ t('bench.inputType') }}</span>
        <label v-for="tp in inputTypes" :key="tp" style="font-size: 0.85rem; cursor: pointer">
          <input type="radio" v-model="inputType" :value="tp" :disabled="benchRunning" /> {{ t('bench.' + tp) }}
        </label>
      </div>
      <textarea v-model="inputText" :placeholder="t('bench.placeholder')" rows="5"></textarea>
      <div style="display: flex; align-items: center; gap: 12px; margin-top: 12px">
        <button class="btn btn-primary" :disabled="!canRun || benchRunning" @click="doRun">{{ t('bench.runTest') }}</button>
        <label class="btn btn-ghost" style="cursor: pointer">
          {{ t('bench.chooseFile') }}
          <input type="file" accept=".txt" style="display: none" @change="loadFile" />
        </label>
        <span style="font-size: 0.78rem; color: var(--muted)">{{ fileName }}</span>
      </div>
    </div>

    <!-- Log -->
    <div class="card">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px">
        <h3 style="color: var(--muted); font-weight: 500">{{ t('bench.logTitle') }}</h3>
        <div style="display: flex; align-items: center; gap: 6px; font-size: 0.85rem">
          <span class="dot" :class="dotClass"></span>
          <span style="color: var(--muted)">{{ statusLabel }}</span>
        </div>
      </div>
      <div class="log-box" ref="logBoxRef">
        <div v-if="!logLines.length" class="empty" style="padding: 60px">{{ t('bench.logPlaceholder') }}</div>
        <div v-for="(line, i) in logLines" :key="i" :class="logLineClass(line)">{{ line }}</div>
      </div>
    </div>

    <!-- Converter -->
    <div class="card" style="margin-top: 16px">
      <h2 style="color: var(--muted); font-weight: 500; margin-bottom: 12px">{{ t('bench.converterTitle') }}</h2>
      <div style="display: flex; gap: 16px; margin-bottom: 10px; align-items: center">
        <span style="font-size: 0.85rem; color: var(--muted); font-weight: 500">{{ t('bench.inputType') }}</span>
        <label style="font-size: 0.85rem; cursor: pointer"><input type="radio" v-model="cvtType" value="mnemonic" /> {{ t('bench.cvtMnemonic') }}</label>
        <label style="font-size: 0.85rem; cursor: pointer"><input type="radio" v-model="cvtType" value="privkey" /> {{ t('bench.cvtPrivkey') }}</label>
      </div>
      <textarea v-model="cvtInput" :placeholder="t('bench.cvtPlaceholder')" rows="3"></textarea>
      <div style="display: flex; align-items: center; gap: 12px; margin-top: 12px">
        <button class="btn btn-primary" :disabled="cvtLoading" @click="doConvert">{{ t('bench.convert') }}</button>
        <span style="font-size: 0.78rem; color: var(--muted)">{{ t('bench.cvtHint') }}</span>
      </div>
      <div v-if="cvtResults" style="margin-top: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; max-height: 360px; overflow-y: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; line-height: 1.9">
        <div v-if="cvtResults.type === 'mnemonic'">
          <div style="color: var(--accent); font-weight: 600; margin-bottom: 8px">Mnemonic → PrivKey + Address</div>
          <div v-for="(k, i) in cvtResults.results" :key="i" style="margin-bottom: 6px; padding: 4px 0; border-bottom: 1px solid var(--border)">
            <div style="color: var(--muted); font-size: 0.72rem">{{ k.path }}</div>
            <div><span style="color: var(--green)">WIF:</span> {{ k.privkey_wif }}</div>
            <div><span style="color: var(--orange)">Hex:</span> {{ k.privkey_hex }}</div>
            <div><span style="color: var(--accent)">Addr:</span> {{ k.address }}</div>
          </div>
        </div>
        <div v-else>
          <div style="color: var(--accent); font-weight: 600; margin-bottom: 8px">PrivKey → Address</div>
          <div v-for="(k, i) in cvtResults.results" :key="i" style="margin-bottom: 4px">
            <span style="color: var(--muted)">{{ k.path }}:</span> <span style="color: var(--accent)">{{ k.address }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '../composables/useApi'

const { t } = useI18n()
const api = useApi()

const nodesData = ref([])
const selectedNodeId = ref('')
const selectedNode = computed(() => nodesData.value.find(n => n.node_id === selectedNodeId.value) || null)
const benchMode = ref('cpu')
const canGpu = computed(() => selectedNode.value?.gpu_available || false)
const canRun = computed(() => selectedNode.value && !selectedNode.value.enabled)

const inputTypes = ['mnemonic', 'address', 'privkey']
const inputType = ref('mnemonic')
const inputText = ref('')
const fileName = ref('')
const benchRunning = ref(false)
const logLines = ref([])
const logBoxRef = ref(null)
let pollTimer = null
let lastLen = 0

const dotClass = computed(() => benchRunning.value ? 'dot-run' : logLines.value.length ? 'dot-done' : 'dot-idle')
const statusLabel = computed(() => benchRunning.value ? t('bench.running') : logLines.value.length ? t('bench.done') : t('bench.waiting'))

const hintText = computed(() => {
  const n = selectedNode.value
  if (!n) {
    const hasPaused = nodesData.value.some(x => x.status === 'online' && !x.enabled)
    return hasPaused ? t('bench.selectHint') : nodesData.value.some(x => x.status === 'online') ? t('bench.allRunning') : t('bench.selectHint')
  }
  if (n.enabled) return t('bench.nodeRunning')
  return n.gpu_available ? 'GPU: ' + n.gpu_name : t('bench.cpuOnly') + (n.gpu_error ? ' (' + n.gpu_error + ')' : '')
})
const hintColor = computed(() => {
  const n = selectedNode.value
  if (!n) return 'var(--orange)'
  if (n.enabled) return 'var(--red)'
  return 'var(--muted)'
})

// Converter
const cvtType = ref('mnemonic')
const cvtInput = ref('')
const cvtLoading = ref(false)
const cvtResults = ref(null)

let nodeTimer = null
async function loadNodes() {
  try {
    const c = await api.getClusterStatus()
    nodesData.value = c.nodes || []
    onNodeSelect()
  } catch {}
}
function onNodeSelect() {
  const n = selectedNode.value
  if (n) {
    benchMode.value = (n.compute_mode || 'cpu')
  }
}
async function setMode(m) {
  if (!selectedNode.value) { alert(t('bench.selectFirst')); return }
  const r = await api.switchNodeMode(selectedNode.value.node_id, m)
  if (!r.ok) alert(r.error || 'unknown')
  else { await loadNodes(); onNodeSelect() }
}
function loadFile(e) {
  const f = e.target.files[0]
  if (!f) return
  fileName.value = f.name
  const r = new FileReader()
  r.onload = ev => { inputText.value = ev.target.result }
  r.readAsText(f)
}
function logLineClass(line) {
  if (line.includes('HIT')) return 'hit'
  if (line.startsWith('===')) return 'head'
  if (line.includes('failed')) return 'warn'
  return ''
}
async function doRun() {
  if (!selectedNode.value) { alert(t('bench.selectFirst')); return }
  if (!inputText.value.trim()) { alert(t('bench.enterContent')); return }
  benchRunning.value = true
  logLines.value = []
  lastLen = 0
  try {
    const d = await api.runBench({ type: inputType.value, content: inputText.value.trim(), node_id: selectedNode.value.node_id })
    if (!d.ok) { alert(d.error || 'Error'); benchRunning.value = false; return }
    pollTimer = setInterval(pollLog, 250)
  } catch { benchRunning.value = false }
}
async function pollLog() {
  try {
    const d = await api.getBenchLog()
    if (d.lines.length > lastLen) {
      logLines.value.push(...d.lines.slice(lastLen))
      lastLen = d.lines.length
      await nextTick()
      if (logBoxRef.value) logBoxRef.value.scrollTop = logBoxRef.value.scrollHeight
    }
    if (d.done) { clearInterval(pollTimer); benchRunning.value = false }
  } catch {}
}
async function doConvert() {
  if (!cvtInput.value.trim()) { alert(t('bench.enterContent')); return }
  cvtLoading.value = true
  try {
    const d = await api.convert({ type: cvtType.value, content: cvtInput.value.trim(), depth: 3 })
    if (!d.ok) { cvtResults.value = null; alert(d.error); return }
    cvtResults.value = d
  } catch (e) { alert('Request failed: ' + e) }
  finally { cvtLoading.value = false }
}

onMounted(() => { loadNodes(); nodeTimer = setInterval(loadNodes, 10000) })
onUnmounted(() => { clearInterval(nodeTimer); clearInterval(pollTimer) })
</script>

<style scoped>
.mode-switch {
  display: flex; gap: 0; padding: 3px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border);
}
.mode-switch button {
  padding: 6px 16px; border: none; border-radius: 6px; font-size: 0.85rem; font-weight: 600;
  cursor: pointer; transition: all 0.15s; background: transparent; color: var(--muted);
}
.mode-switch button.active { background: var(--accent); color: #fff; box-shadow: 0 1px 3px rgba(0,102,255,.3); }
.mode-switch button:disabled { opacity: 0.3; cursor: not-allowed; }
</style>
