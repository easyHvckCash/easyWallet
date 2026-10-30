import axios from 'axios'

const http = axios.create({
  baseURL: '/',
  timeout: 30000,
  withCredentials: true,
})

// Auto-redirect to /login on 401
http.interceptors.response.use(
  (resp) => resp,
  (err) => {
    if (err.response && err.response.status === 401) {
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

export function useApi() {
  // ---- Scanner / Master ----
  const getStatus       = () => http.get('/api/status').then(r => r.data)
  const getSysinfo      = () => http.get('/api/sysinfo').then(r => r.data)
  const getClusterStatus = () => http.get('/api/cluster/status').then(r => r.data)
  const startDispatch   = () => http.post('/api/start').then(r => r.data)
  const stopDispatch    = () => http.post('/api/stop').then(r => r.data)
  const exportJson      = () => http.post('/api/export').then(r => r.data)
  const setQueueLimit   = (limit) => http.post('/api/set_queue_limit', { limit }).then(r => r.data)
  const setNodeLimit    = (nodeId, limit) => http.post('/api/set_node_limit', { node_id: nodeId, limit }).then(r => r.data)
  const toggleNode      = (nodeId, enabled) => http.post('/api/nodes/enable', { node_id: nodeId, enabled }).then(r => r.data)
  const switchNodeMode  = (nodeId, mode) => http.post('/api/nodes/switch_mode', { node_id: nodeId, mode }).then(r => r.data)

  // ---- Bench ----
  const runBench   = (data) => http.post('/api/bench/run', data).then(r => r.data)
  const getBenchLog = () => http.get('/api/bench/log').then(r => r.data)
  const convert    = (data) => http.post('/api/convert', data).then(r => r.data)

  // ---- Results ----
  const getResults = () => http.get('/api/results').then(r => r.data)

  // ---- Stats ----
  const getDirStats = () => http.get('/api/dir_stats').then(r => r.data)

  // ---- POCs ----
  const getPocsList    = () => http.get('/api/pocs/list').then(r => r.data)
  const getPocsStatus  = () => http.get('/api/pocs/status').then(r => r.data)
  const startPoc       = (data) => http.post('/api/pocs/start', data).then(r => r.data)
  const stopPoc        = (data) => http.post('/api/pocs/stop', data).then(r => r.data)
  const getPocLog      = (data) => http.post('/api/pocs/log', data).then(r => r.data)
  const reloadPocs     = () => http.post('/api/pocs/reload').then(r => r.data)
  const getReloadInfo  = () => http.get('/api/pocs/reload_info').then(r => r.data)
  const savePocSettings = (data) => http.post('/api/pocs/settings', data).then(r => r.data)
  const editPocProgress = (data) => http.post('/api/pocs/edit_progress', data).then(r => r.data)

  // ---- Bench result ----
  const postBenchResult = (data) => http.post('/api/bench/result', data).then(r => r.data)

  // ---- Upload ----
  const getUploadConfig  = () => http.get('/api/upload/config').then(r => r.data)
  const saveUploadConfig = (configs) => http.post('/api/upload/config/save', { configs }).then(r => r.data)
  const getUploadStatus  = () => http.get('/api/upload/status').then(r => r.data)
  const triggerUpload    = (fileKey) => http.post('/api/upload/trigger', { file_key: fileKey }).then(r => r.data)

  // ---- Auth ----
  const login    = (username, password) => http.post('/api/login', { username, password }).then(r => r.data)
  const logout   = () => http.post('/api/logout').then(r => r.data)
  const checkAuth = () => http.get('/api/auth/check').then(r => r.data)

  return {
    getStatus, getSysinfo, getClusterStatus,
    startDispatch, stopDispatch, exportJson,
    setQueueLimit, setNodeLimit, toggleNode, switchNodeMode,
    runBench, getBenchLog, convert, postBenchResult,
    getResults,
    getDirStats,
    getPocsList, getPocsStatus, startPoc, stopPoc, getPocLog,
    reloadPocs, getReloadInfo, savePocSettings, editPocProgress,
    getUploadConfig, saveUploadConfig, getUploadStatus, triggerUpload,
    login, logout, checkAuth,
  }
}
