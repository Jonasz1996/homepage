<script>
  // Terminal-venster zoals in aiverslag: drie bolletjes en een prompt in de titelbalk.
  let { title = '', prompt = 'root@jbogaert:~#', glow = false, children, right = null, class: cls = '' } = $props()
</script>

<section class="card {cls}" class:glow>
  <div class="bar">
    <span class="dots"><i></i><i></i><i></i></span>
    <span class="title">{prompt} {title}</span>
    {#if right}<span class="right">{@render right()}</span>{/if}
  </div>
  {@render children()}
</section>
