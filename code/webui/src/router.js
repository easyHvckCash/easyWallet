import { createRouter, createWebHistory } from 'vue-router'

const routes = [
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

export default router
