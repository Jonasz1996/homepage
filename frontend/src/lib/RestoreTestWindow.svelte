<script>
  import Modal from './Modal.svelte'
  import RestoreTest from './RestoreTest.svelte'

  let { onclose } = $props()
</script>

<Modal title="pct restore --test" {onclose} wide>
  <RestoreTest />
</Modal>
