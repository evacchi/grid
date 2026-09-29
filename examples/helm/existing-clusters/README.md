# Existing-Cluster Helm Installation

See the canonical guide at [docs/installation/existing-clusters.md](../../../docs/installation/existing-clusters.md).

## File Layout

```text
inventory.example.yaml    Example inventory (copy, fill, do not commit)
scripts/
  preflight.sh            Validate prerequisites and inventory
  install.sh              Install AGN + Praxis on all clusters
  verify.sh               Run post-install verification
  uninstall.sh            Clean up Helm releases
combined-site/
  values/                 Per-site Helm values for combined topology
dedicated-edge/
  values/                 Per-site Helm values for dedicated-edge topology
```
