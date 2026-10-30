import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import { createI18n } from 'vue-i18n'
import en from './i18n/en'
import zh from './i18n/zh'
import './assets/global.css'

const savedLang = localStorage.getItem('dash_lang') || 'en'

const i18n = createI18n({
  legacy: false,
  locale: savedLang,
  fallbackLocale: 'en',
  messages: { en, zh },
})

const app = createApp(App)
app.use(router)
app.use(i18n)
app.mount('#app')
