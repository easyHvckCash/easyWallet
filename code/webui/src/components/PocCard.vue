<template>
  <div class="poc-card">
    <div class="poc-top">
      <div style="flex: 1">
        <div style="display: flex; align-items: center; gap: 8px"><h3>{{ poc.name }}</h3></div>
        <div style="display: flex; gap: 6px; flex-wrap: wrap; margin: 6px 0 10px">
          <span class="badge" :class="statusBadgeClass">{{ statusText }}</span>
          <span v-if="poc.output_type" class="badge" :class="poc.output_type === 'mnemonic' ? 'badge-mnemonic' : 'badge-privkey'">{{ poc.output_type }}</span>
          <span class="badge" :class="poc.public ? 'badge-running' : 'badge-idle'">{{ poc.public ? t('pocs.publicLabel') : t('pocs.privateLabel') }}</span>
        </div>
        <div class="poc-meta-grid">
          <span class="meta-key">ID</span><span class="meta-val">{{ poc.id }}</span>
          <template v-if="poc.generation_speed"><span class="meta-key">Speed</span><span class="meta-val">{{ poc.generation_speed }}</span></template>
          <span class="meta-key">Severity</span><span class="meta-val">{{ poc.severity || '—' }}</span>
          <template v-if="poc.coverage_time_range"><span class="meta-key">Coverage</span><span class="meta-val">{{ poc.coverage_time_range }}</span></template>
          <span class="meta-key">Versions</span><span class="meta-val">{{ (poc.affected_versions || []).join(', ') || '—' }}</span>
          <span class="meta-key">Product</span><span class="meta-val">{{ poc.vendor || '—' }}</span>
          <template v-if="poc.note"><span class="meta-key">Note</span><span class="meta-val">{{ poc.note }}</span></template>
        </div>
      </div>
      <div class="poc-actions">
        <button v-if="!poc.has_generator" class="btn btn-sm btn-ghost" disabled>{{ t('pocs.noGenerator') }}</button>
        <button v-else-if="isRunning" class="btn btn-sm btn-danger" @click="$emit('stop', poc.id)">{{ t('pocs.stop') }}</button>
        <button v-else class="btn btn-sm btn-success" @click="$emit('start', poc.id, poc.name)">Start</button>
        <button v-if="!isRunning" class="btn btn-sm btn-ghost" @click="$emit('edit', poc.id, poc.name)">{{ t('pocs.edit') }}</button>
        <button class="btn btn-sm btn-ghost" @click="$emit('detail', poc.id, poc.name)">{{ t('pocs.details') }}</button>
      </div>
    </div>

    <!-- Progress bar -->
    <div v-if="progress && progress.total_space" style="margin-top: 10px">
      <div class="progress-track"><div class="progress-fill" :style="{ width: pctStr + '%' }"></div></div>
      <div style="display: flex; justify-content: space-between; margin-top: 5px; font-size: 0.78rem; color: var(--muted)">
        <span>{{ pctStr }}% — {{ (progress.total_generated || 0).toLocaleString() }} / {{ progress.total_space.toLocaleString() }}</span>
        <span>{{ speedStr }}{{ elapsedStr }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const props = defineProps({ poc: Object, runStatus: Object })
defineEmits(['start', 'stop', 'detail', 'edit'])

const run = computed(() => (props.runStatus.pocs || []).find(p => p.poc_id === props.poc.id))
const isRunning = computed(() => run.value?.status === 'running')
const isFinished = computed(() => run.value?.status === 'finished')

const statusBadgeClass = computed(() => isRunning.value ? 'badge-running' : isFinished.value ? 'badge-finished' : 'badge-idle')
const statusText = computed(() => isRunning.value ? t('pocs.running') : isFinished.value ? t('pocs.finished') : t('pocs.idle'))

const progress = computed(() => {
  const p = run.value?.progress
  if (p) return p
  return props.runStatus.all_progress?.[props.poc.id] || null
})
const pctStr = computed(() => {
  const p = progress.value
  if (!p?.total_space) return '0'
  return Math.min(100, ((p.total_generated || 0) / p.total_space * 100)).toFixed(4)
})
const speedStr = computed(() => {
  const elapsed = run.value?.elapsed_secs || 0
  const done = progress.value?.total_generated || 0
  if (elapsed <= 0) return '—'
  return (done / elapsed).toFixed(0) + '/s'
})
const elapsedStr = computed(() => {
  const s = run.value?.elapsed_secs || 0
  if (s <= 0) return ''
  if (s < 60) return ' | ' + Math.round(s) + 's'
  if (s < 3600) return ' | ' + Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's'
  return ' | ' + Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'
})
</script>

<style scoped>
.poc-card {
  background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px;
  transition: all 0.15s;
}
.poc-card:hover { border-color: var(--accent); box-shadow: 0 2px 12px rgba(59,130,246,.08); }
.poc-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.poc-actions { display: flex; gap: 6px; align-items: center; flex-shrink: 0; }
.poc-meta-grid {
  display: grid; grid-template-columns: auto 1fr; gap: 3px 12px; font-size: 0.85rem; line-height: 1.6;
}
.meta-key { font-weight: 600; color: var(--text); }
.meta-val { color: var(--muted); }
</style>
