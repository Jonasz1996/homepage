<script>
  import { onMount } from 'svelte'
  import { api } from './lib/api.js'
  import Auth from './lib/Auth.svelte'
  import Dashboard from './lib/Dashboard.svelte'

  let state = $state(null)
  let error = $state('')

  async function refresh() {
    try {
      state = await api('/auth/state')
      error = ''
      document.title = state.site_name || 'homepage'
    } catch (e) {
      error = e.message
    }
  }

  onMount(() => {
    refresh()
    const onUnauth = () => refresh()
    window.addEventListener('hp:unauth', onUnauth)
    return () => window.removeEventListener('hp:unauth', onUnauth)
  })
</script>

{#if error}
  <p class="boot err">API niet bereikbaar: {error}</p>
{:else if !state}
  <p class="boot hint">Laden...<span class="cur"></span></p>
{:else if state.mfa_ok}
  <Dashboard user={state.user} onlogout={refresh} />
{:else}
  <Auth auth={state} ondone={refresh} />
{/if}

<style>
  .boot { text-align: center; margin-top: 30vh }
</style>
