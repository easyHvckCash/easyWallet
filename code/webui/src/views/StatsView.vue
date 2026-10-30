<template>
  <div>
    <div class="table-wrap" style="margin-bottom: 24px">
      <table>
        <thead>
          <tr>
            <th>{{ t('stats.pocDir') }}</th>
            <th>{{ t('stats.filesProc') }}</th>
            <th>Mnemonic</th>
            <th>PrivKey</th>
            <th>{{ t('stats.hitsCol') }}</th>
            <th>{{ t('stats.totalHits') }}</th>
            <th>{{ t('stats.lastUp') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!pocKeys.length">
            <td colspan="7" class="empty">{{ t('stats.noData') }}</td>
          </tr>
          <tr v-for="k in pocKeys" :key="k">
            <td><b>{{ k === '.' ? '(root)' : k }}</b></td>
            <td class="num">{{ pocData[k].files_processed }}</td>
            <td class="num">{{ pocData[k].mnemonics_scanned.toLocaleString() }}</td>
            <td class="num">{{ (pocData[k].privkeys_scanned || 0).toLocaleString() }}</td>
            <td class="num">{{ pocData[k].hits }}</td>
            <td class="num">-</td>
            <td>{{ fmtTime(pocData[k].last_time) }}</td>
          </tr>
          <tr v-if="pocKeys.length" style="background: var(--hover-bg); font-weight: 700">
            <td>{{ t('stats.total') }}</td>
            <td class="num">{{ totals.files }}</td>
            <td class="num">{{ totals.mn.toLocaleString() }}</td>
            <td class="num">{{ totals.pk.toLocaleString() }}</td>
            <td class="num">{{ totals.hits }}</td>
            <td class="num" style="color: var(--green)">{{ uniqueCount }}</td>
            <td></td>
          </tr>
        </tbody>
      </table>
    </div>

    <h3 class="section-title">{{ t('stats.nodeContrib') }}</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Node</th><th>POC</th><th>Tasks Done</th><th>Scanned</th><th>Hits</th><th>Last Activity</th></tr></thead>
        <tbody>
          <tr v-if="!nodeData.length">
            <td colspan="6" class="empty">{{ t('stats.noNodeData') }}</td>
          </tr>
          <tr v-for="(n, i) in nodeData" :key="i">
            <td><b>{{ n.node_id.substring(0, 12) }}</b></td>
            <td>{{ n.poc_id }}</td>
            <td class="num">{{ n.tasks }}</td>
            <td class="num">{{ n.scanned.toLocaleString() }}</td>
            <td class="num">{{ n.hits }}</td>
            <td>{{ fmtTime(n.last_time) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useApi } from '../composables/useApi'

const { t } = useI18n()
const api = useApi()

const pocData = ref({})
const pocKeys = ref([])
const nodeData = ref([])
const uniqueCount = ref(0)

const totals = computed(() => {
  let files = 0, mn = 0, pk = 0, hits = 0
  for (const k of pocKeys.value) {
    const e = pocData.value[k]
    files += e.files_processed
    mn += e.mnemonics_scanned
    pk += (e.privkeys_scanned || 0)
    hits += e.hits
  }
  return { files, mn, pk, hits }
})

function fmtTime(ts) {
  if (!ts || ts.length < 5) return ''
  try { return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString() } catch { return ts }
}

let timer = null
async function load() {
  try {
    const [raw, rData] = await Promise.all([api.getDirStats(), api.getResults()])
    const d = raw.by_poc || raw
    pocData.value = d
    pocKeys.value = Object.keys(d).sort((a, b) => a === '.' ? -1 : b === '.' ? 1 : a.localeCompare(b))
    nodeData.value = raw.by_node || []
    uniqueCount.value = rData.count || 0
  } catch {}
}

onMounted(() => { load(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.num { font-variant-numeric: tabular-nums; font-weight: 600; }
</style>
