import { createRouter, createWebHistory } from 'vue-router'
import axios from 'axios'

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { public: true } },
  { path: '/', name: 'scanner', component: () => import('./views/ScannerView.vue') },
  { path: '/bench', name: 'bench', component: () => import('./views/BenchView.vue') },
  { path: '/results', name: 'results', component: () => import('./views/ResultsView.vue') },
  { path: '/stats', name: 'stats', component: () => import('./views/StatsView.vue') },
  { path: '/pocs', name: 'pocs', component: () => import('./views/PocsView.vue') },
  { path: '/about', name: 'about', component: () => import('./views/AboutView.vue') },
  { path: '/upload', name: 'upload', component: () => import('./views/UploadView.vue') },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

let authChecked = false
let isAuthed = false

router.beforeEach(async (to) => {
  if (to.meta.public) return true
  if (!authChecked) {
    try {
      const resp = await axios.get('/api/auth/check', { withCredentials: true })
      isAuthed = resp.data && resp.data.ok
    } catch {
      isAuthed = false
    }
    authChecked = true
  }
  if (!isAuthed) {
    return { name: 'login' }
  }
  return true
})

// Reset auth state when navigating to login
router.afterEach((to) => {
  if (to.name === 'login') {
    authChecked = false
    isAuthed = false
  }
})

export function setAuthed(val) {
  authChecked = true
  isAuthed = val
}

export default router
