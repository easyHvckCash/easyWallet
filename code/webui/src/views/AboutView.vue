<template>
  <div style="max-width: 900px">
    <!-- Why This Work Matters -->
    <div class="card about-card">
      <h2>{{ t('about.whyTitle') }}</h2>
      <p>A Bitcoin private key is a 256-bit random number with 2<sup>256</sup> (&asymp;1.16&times;10<sup>77</sup>) possible values &mdash; a number so vast it exceeds the total atoms in the observable universe. If keys were truly random, brute-force is physically impossible.</p>
      <p>But in reality, nobody manually picks 256 random bits. Everyone relies on wallet software to generate their private keys. The problem is: <b>some wallet products used naive implementations for key generation</b>, collapsing the theoretical 2<sup>256</sup> space down to 2<sup>32</sup> or even smaller.</p>
      <p>By enumerating these tiny spaces, an attacker can reconstruct every affected wallet's private key and steal user funds. This is not theoretical &mdash; multiple public incidents have proven the attacks work:</p>
      <ul>
        <li>Milk Sad (CVE-2023-39910) &mdash; libbitcoin bx seed, 2³² keys, $900K+ stolen</li>
        <li>Coldcard Yasmarang &mdash; Mk3 TRNG bypass, 2³² keys, ~594 BTC stolen</li>
        <li>Trust Wallet (CVE-2023-31290) &mdash; WASM MT19937, 2³² keys</li>
        <li>Randstorm (Unciphered 2023) &mdash; bitaddress.org IE, 2³¹ keys</li>
        <li>Ill Bloom (CVE-2026-71851) &mdash; CryptoJS MWC, 2⁴⁰ keys, $5M+ stolen</li>
      </ul>
      <p>You have to respect the early movers &mdash; they had both the insight to identify these flaws and the execution to act on them. But it's not too late. The goal of this project is: <b>let a home PC join this game</b>. With GPU acceleration and distributed computing, a single RTX 4060 Ti can sweep a 2<sup>32</sup> key space in under 24 hours.</p>
    </div>

    <!-- Severity Rating -->
    <div class="card about-card">
      <h2>{{ t('about.severityTitle') }}</h2>
      <div class="severity-grid">
        <div>
          <p><b>Criteria:</b> Based on effective entropy of generated key material. BIP-39 requires at least 128-bit cryptographically secure random entropy.</p>
          <p><b>Ratings:</b></p>
          <div style="margin-left: 8px">
            • <span style="color: var(--muted)">Low</span> — ≤80 bit<br />
            • <span style="color: var(--orange)">Medium</span> — ≤50 bit<br />
            • <span style="color: var(--red)">High</span> — ≤40 bit<br />
            • <span style="color: #7c2d12; font-weight: 700">Critical</span> — ≤30 bit
          </div>
        </div>
        <div>
          <p><b>Compute Reference (brute-force 2³² keys):</b></p>
          <div style="margin-left: 8px">
            • RTX 4060 Ti: ~23.9h (50K/s)<br />
            • RTX 2060 Super: ~58.2h (20.5K/s)<br />
            • B300 x1: ~6.8h (175K/s)<br />
            • B300 x8: ~51min (1.4M/s)<br />
            • B300 x64: ~6.4min (11.2M/s)
          </div>
          <p style="margin-top: 12px"><b>6-month attack surface:</b></p>
          <div style="margin-left: 8px">
            • B300 x1 → ≤2⁴¹ unsafe<br />
            • B300 x8 → ≤2⁴⁴ unsafe<br />
            • B300 x64 → ≤2⁴⁷ unsafe
          </div>
        </div>
      </div>
    </div>

    <!-- Donate -->
    <div class="card about-card">
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px">
        <svg width="22" height="22" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="16" fill="#f7931a"/><path d="M22.5 14.2c.3-2-1.2-3.1-3.3-3.8l.7-2.7-1.6-.4-.7 2.7c-.4-.1-.9-.2-1.3-.3l.7-2.7-1.6-.4-.7 2.7c-.3-.1-.7-.2-1-.2l-2.2-.6-.4 1.7s1.2.3 1.2.3c.6.2.8.6.7 1l-.7 2.9c0 0 .1 0 .1 0l-.1 0-1 4c-.1.2-.3.6-.8.4 0 0-1.2-.3-1.2-.3l-.8 1.8 2.1.5c.4.1.8.2 1.2.3l-.7 2.8 1.6.4.7-2.7c.4.1.9.2 1.3.3l-.7 2.7 1.6.4.7-2.8c2.9.6 5.1.3 6-2.3.7-2.1 0-3.3-1.5-4 1.1-.3 1.9-1 2.1-2.5zm-3.8 5.3c-.5 2.1-4 1-5.2.7l.9-3.7c1.1.3 4.8.8 4.3 3zm.5-5.4c-.5 1.9-3.4.9-4.3.7l.8-3.4c1 .2 4 .7 3.5 2.7z" fill="#fff"/></svg>
        <h2 style="margin-bottom: 0">{{ t('about.donateTitle') }}</h2>
      </div>
      <div class="donate-addr">33Eow2BuYrqp9AaN23wsgau1uWWTrSrci5</div>
      <p style="font-size: 0.85rem; color: var(--muted); margin-top: 6px">{{ t('about.donateNote') }}</p>
      <ol style="font-size: 0.85rem; color: var(--muted); margin-top: 10px; line-height: 1.8; padding-left: 18px">
        <li v-for="(step, i) in tm('about.donateSteps')" :key="i" v-html="step"></li>
      </ol>
    </div>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
const { t, tm } = useI18n()
</script>

<style scoped>
.about-card { padding: 24px 28px; margin-bottom: 20px; }
.about-card h2 { font-size: 1.2rem; font-weight: 700; margin-bottom: 14px; color: var(--accent); }
.about-card p { font-size: 0.92rem; line-height: 1.9; margin-bottom: 12px; }
.about-card ul { margin-left: 20px; margin-bottom: 12px; font-size: 0.92rem; line-height: 1.8; color: var(--muted); }
.about-card b { color: var(--text); }
.donate-addr {
  font-family: 'SF Mono', Consolas, monospace; font-size: 0.92rem;
  padding: 10px 14px; background: #f6f8fa; border: 1px solid var(--border);
  border-radius: 6px; word-break: break-all;
}
.severity-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 20px; font-size: 0.85rem; line-height: 1.8;
}
@media (max-width: 700px) { .severity-grid { grid-template-columns: 1fr; } }
</style>
