<template>
  <div class="login-page">
    <div class="login-card">
      <h1 class="login-logo">easyWallet</h1>
      <p class="login-sub">Dashboard Login</p>
      <form @submit.prevent="doLogin" class="login-form">
        <div class="field">
          <label>Username</label>
          <input type="text" v-model="username" autocomplete="username" autofocus />
        </div>
        <div class="field">
          <label>Password</label>
          <input type="password" v-model="password" autocomplete="current-password" />
        </div>
        <p v-if="error" class="login-error">{{ error }}</p>
        <button type="submit" class="btn btn-primary login-btn" :disabled="loading">
          {{ loading ? '...' : 'Sign In' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useApi } from '../composables/useApi'
import { setAuthed } from '../router'

const router = useRouter()
const api = useApi()

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function doLogin() {
  error.value = ''
  loading.value = true
  try {
    const d = await api.login(username.value, password.value)
    if (d.ok) {
      setAuthed(true)
      router.push('/')
    } else {
      error.value = d.error || 'Login failed'
    }
  } catch (e) {
    error.value = 'Connection failed'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg);
}
.login-card {
  width: 380px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 40px 36px;
  box-shadow: var(--shadow-md);
  text-align: center;
}
.login-logo {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 4px;
}
.login-sub {
  font-size: 0.85rem;
  color: var(--muted);
  margin-bottom: 28px;
}
.login-form {
  display: flex;
  flex-direction: column;
  gap: 16px;
  text-align: left;
}
.login-form .field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.login-form label {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.login-form input {
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.92rem;
  color: var(--text);
  background: var(--bg);
  transition: border-color 0.15s;
}
.login-form input:focus {
  outline: none;
  border-color: var(--accent);
}
.login-btn {
  width: 100%;
  padding: 10px;
  margin-top: 4px;
  font-size: 0.92rem;
}
.login-error {
  color: var(--red);
  font-size: 0.85rem;
  text-align: center;
  margin: 0;
}
</style>
