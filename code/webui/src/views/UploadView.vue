<template>
  <div>
    <!-- Header -->
    <div class="card" style="margin-bottom: 20px; padding: 20px 24px">
      <h2 style="margin-bottom: 6px">{{ t('upload.title') }}</h2>
      <p style="font-size: 0.85rem; color: var(--muted); line-height: 1.6">{{ t('upload.desc') }}</p>
    </div>

    <!-- Config Cards -->
    <div class="config-grid">
      <div v-for="(cfg, i) in configs" :key="cfg.file_key" class="card config-card">
        <div class="config-header">
          <div style="display: flex; align-items: center; gap: 8px">
            <span class="file-badge">{{ cfg.file_key }}</span>
            <span class="badge" :class="cfg.enabled ? 'badge-running' : 'badge-idle'">
              {{ cfg.enabled ? t('upload.active') : t('upload.inactive') }}
            </span>
          </div>
          <label class="toggle-label">
            <input type="checkbox" v-model="configs[i].enabled" />
            <span>{{ t('upload.enabledLabel') }}</span>
          </label>
        </div>

        <div class="config-fields">
          <label class="field">
            <span class="field-label">{{ t('upload.urlLabel') }}</span>
            <input type="text" v-model="configs[i].url" :placeholder="t('upload.urlPlaceholder')" />
          </label>
          <label class="field">
            <span class="field-label">{{ t('upload.tokenLabel') }}</span>
            <input type="password" v-model="configs[i].token" :placeholder="t('upload.tokenPlaceholder')" autocomplete="off" />
          </label>
          <label class="field field-short">
            <span class="field-label">{{ t('upload.intervalLabel') }}</span>
            <input type="number" v-model.number="configs[i].interval_secs" min="10" max="86400" style="width: 100px" />
          </label>
        </div>

        <div style="display: flex; gap: 8px; margin-top: 14px">
          <button class="btn btn-primary btn-sm" :disabled="triggering[cfg.file_key]" @click="doTrigger(cfg.file_key)">
            {{ triggering[cfg.file_key] ? '...' : t('upload.trigger') }}
          </button>
          <span v-if="lastResult[cfg.file_key]" style="font-size: 0.78rem; align-self: center" :style="{ color: lastResult[cfg.file_key].ok ? 'var(--green)' : 'var(--red)' }">
            {{ lastResult[cfg.file_key].msg }}
          </span>
        </div>
      </div>
    </div>

    <!-- Save button -->
    <div style="margin: 20px 0; display: flex; gap: 12px; align-items: center">
      <button class="btn btn-success" :disabled="saving" @click="doSave">{{ t('upload.save') }}</button>
      <span v-if="saveMsg" style="font-size: 0.85rem; color: var(--green)">{{ saveMsg }}</span>
    </div>

    <!-- Logs -->
    <div class="section-title">{{ t('upload.logsTitle') }}</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{{ t('upload.colTime') }}</th>
            <th>{{ t('upload.colFile') }}</th>
            <th>{{ t('upload.colResult') }}</th>
            <th>{{ t('upload.colMessage') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!logs.length">
            <td colspan="4" class="empty">{{ t('upload.noLogs') }}</td>
          </tr>
          <tr v-for="(log, i) in reversedLogs" :key="i">
            <td style="white-space: nowrap; font-size: 0.78rem; color: var(--muted)">{{ log.time }}</td>
            <td><span class="file-badge file-badge-sm">{{ log.file_key }}</span></td>
            <td>
              <span class="badge" :class="log.success ? 'badge-running' : 'badge-error'">
                {{ log.success ? t('upload.success') : t('upload.fail') }}
              </span>
            </td>
            <td style="font-size: 0.78rem; color: var(--muted); max-width: 400px; word-break: break-all">{{ log.message }}</td>
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

const configs = ref([])
const logs = ref([])
const saving = ref(false)
const saveMsg = ref('')
const triggering = reactive({})
const lastResult = reactive({})

const reversedLogs = computed(() => [...logs.value].reverse())

let timer = null

async function loadConfig() {
  try {
    const d = await api.getUploadConfig()
    if (d.ok) configs.value = d.configs
  } catch {}
}

async function loadStatus() {
  try {
    const d = await api.getUploadStatus()
    if (d.ok) logs.value = d.logs || []
  } catch {}
}

async function doSave() {
  saving.value = true
  saveMsg.value = ''
  try {
    const d = await api.saveUploadConfig(configs.value)
    if (d.ok) saveMsg.value = t('upload.saved')
    else alert(d.error || 'Save failed')
  } catch (e) { alert('Request failed: ' + e) }
  finally { saving.value = false }
  setTimeout(() => { saveMsg.value = '' }, 3000)
}

async function doTrigger(fileKey) {
  triggering[fileKey] = true
  lastResult[fileKey] = null
  try {
    // Auto-save configs before triggering to ensure backend has latest URL/token
    const saveRes = await api.saveUploadConfig(configs.value)
    if (!saveRes.ok) {
      lastResult[fileKey] = { ok: false, msg: saveRes.error || 'Auto-save failed' }
      return
    }
    const d = await api.triggerUpload(fileKey)
    lastResult[fileKey] = { ok: d.ok, msg: d.ok ? t('upload.triggerSuccess') : (d.message || d.error || t('upload.triggerFail')) }
    loadStatus()
  } catch (e) {
    lastResult[fileKey] = { ok: false, msg: String(e) }
  } finally { triggering[fileKey] = false }
}

onMounted(() => {
  loadConfig()
  loadStatus()
  timer = setInterval(loadStatus, 5000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.config-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));
  gap: 16px;
}
.config-card { padding: 20px 24px; }
.config-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.file-badge {
  display: inline-block;
  padding: 3px 10px;
  background: var(--accent);
  color: #fff;
  border-radius: 4px;
  font-size: 0.78rem;
  font-weight: 700;
  font-family: 'JetBrains Mono', monospace;
}
.file-badge-sm {
  font-size: 0.72rem;
  padding: 2px 6px;
}
.toggle-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
  color: var(--muted);
  cursor: pointer;
}
.toggle-label input[type="checkbox"] {
  width: 16px;
  height: 16px;
  accent-color: var(--accent);
}
.config-fields {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.field-short {
  max-width: 180px;
}
.field-label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.field input {
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  color: var(--text);
  background: var(--bg);
  transition: border-color 0.15s;
}
.field input:focus {
  outline: none;
  border-color: var(--accent);
}
.badge-error {
  background: #fef2f2;
  color: var(--red);
}
</style>
