<script>
  import Maintenance from './Maintenance.svelte'
  import Modal from './Modal.svelte'

  // Alle geplande onderhoudsvensters, voor services en groepen.
  let { onclose, services = [], groups = [] } = $props()
</script>

<Modal title="crontab -e # onderhoud" {onclose}>
  <Maintenance {services} {groups} />
</Modal>
