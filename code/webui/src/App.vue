<template>
  <div class="layout" v-if="route.name !== 'login'">
    <header class="app-header">
      <h1 class="logo">easyWallet</h1>
      <nav class="nav-tabs">
        <router-link
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          :class="{ active: isActive(item.to) }"
        >
          {{ t(item.label) }}
        </router-link>
      </nav>
      <div class="header-actions">
        <button class="lang-btn" @click="toggleLang">{{ t('lang.toggle') }}</button>
        <button class="lang-btn" @click="doLogout">{{ t('nav.logout') }}</button>
      </div>
    </header>
    <main class="view-container">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
  </div>
  <router-view v-else />
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useApi } from './composables/useApi'
import { setAuthed } from './router'

const { t, locale } = useI18n()
const route = useRoute()
const router = useRouter()
const api = useApi()

function isActive(to) {
  if (to === '/') return route.path === '/'
  return route.path.startsWith(to)
}

const navItems = [
  { to: '/', label: 'nav.scanner' },
  { to: '/bench', label: 'nav.bench' },
  { to: '/results', label: 'nav.hits' },
  { to: '/stats', label: 'nav.stats' },
  { to: '/pocs', label: 'nav.pocs' },
  { to: '/about', label: 'nav.about' },
  { to: '/upload', label: 'nav.upload' },
]

function toggleLang() {
  locale.value = locale.value === 'en' ? 'zh' : 'en'
  localStorage.setItem('dash_lang', locale.value)
}

async function doLogout() {
  try { await api.logout() } catch {}
  setAuthed(false)
  router.push('/login')
}
</script>

<style scoped>
.app-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}

.logo {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text);
  letter-spacing: -0.3px;
}

.nav-tabs {
  display: flex;
  gap: 2px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 3px;
}

.nav-tabs a {
  flex: 1 1 0;
  min-width: 0;
  padding: 7px 12px;
  text-align: center;
  border-radius: 6px;
  font-size: 0.85rem;
  color: var(--muted);
  text-decoration: none;
  transition: background 0.15s, color 0.15s;
  font-weight: 600;
  white-space: nowrap;
}

.nav-tabs a:hover {
  color: var(--text);
  background: var(--hover-bg);
}

.nav-tabs a.active {
  color: #fff;
  background: var(--accent);
}

.header-actions {
  display: flex;
  gap: 6px;
  align-items: center;
}

.lang-btn {
  padding: 4px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--card);
  font-size: 0.85rem;
  cursor: pointer;
  color: var(--muted);
  transition: all 0.15s;
}
.lang-btn:hover {
  border-color: var(--accent);
  color: var(--accent);
}

.view-container {
  min-height: calc(100vh - 100px);
}
</style>
