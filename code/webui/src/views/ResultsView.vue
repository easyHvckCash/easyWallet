<template>
  <div>
    <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 16px">
      <div class="card" style="padding: 10px 20px; display: flex; align-items: center; gap: 8px">
        <span style="color: var(--accent); font-size: 1.4rem; font-weight: 700">{{ hitCount }}</span>
        <span>{{ t('results.hitsLabel') }}</span>
      </div>
      <span style="font-size: 0.85rem; color: var(--muted)">{{ t('results.note') }}</span>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{{ t('results.colAddress') }}</th>
            <th>{{ t('results.colSource') }}</th>
            <th>{{ t('results.colPoc') }}</th>
            <th>{{ t('results.colNode') }}</th>
            <th>{{ t('results.colTime') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="5" class="empty">{{ t('results.loading') }}</td>
          </tr>
          <tr v-else-if="!results.length">
            <td colspan="5" class="empty">{{ error ? t('results.loadFailed') : t('results.noRecords') }}</td>
          </tr>
          <tr v-for="(r, i) in results" :key="i">
            <td class="mono" style="color: var(--accent); font-size: 0.85rem; word-break: break-all">{{ r.address || '-' }}</td>
            <td class="mono" style="font-size: 0.78rem; color: var(--muted); word-break: break-all; max-width: 360px">{{ r.source || '-' }}</td>
            <td>{{ r.poc_id || '-' }}</td>
            <td>{{ r.node_id ? r.node_id.substring(0, 12) : '-' }}</td>
            <td style="font-size: 0.78rem; color: var(--muted); white-space: nowrap">{{ formatTime(r.found_at) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '../composables/useApi'

const { t } = useI18n()
const api = useApi()

const hitCount = ref(0)
const results = ref([])
const loading = ref(true)
const error = ref(false)
let timer = null

function formatTime(ts) {
  if (!ts || ts.length < 5) return '-'
  try {
    const d = new Date(ts)
    if (isNaN(d.getTime())) return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
    return d.toLocaleString()
  } catch { return ts }
}

async function load() {
  try {
    const d = await api.getResults()
    hitCount.value = d.count || 0
    results.value = d.results || []
    error.value = false
  } catch {
    error.value = true
  } finally {
    loading.value = false
  }
}

onMounted(() => { load(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.mono { font-family: 'JetBrains Mono', monospace; }
</style>
