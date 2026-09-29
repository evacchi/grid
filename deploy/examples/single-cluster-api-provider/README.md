# Single Cluster API Provider Example

This example demonstrates a minimal Grid deployment with:

- One `GridNetwork` and `GridSite`
- One `InferenceProvider` pointing to an external API
- Consumer gateway configuration (Praxis AI gateway deployment separate)

This example is not runnable end-to-end by itself. It requires a valid external
API credential and a separately deployed Praxis AI gateway that consumes the
Grid-generated ConfigMap.

## Prerequisites

1. AGN Operator installed (see `../../README.md`)
2. Praxis AI gateway deployment with:
   - `intelligent_route` filter
   - `credential_inject` filter
   - Consumer configuration referencing generated ConfigMaps

## Installation

```bash
# 1. Apply the network and site
kubectl apply -f gridnetwork.yaml
kubectl apply -f gridsite.yaml

# 2. Create a credential Secret from a protected file containing the API token.
#    Do not put the token directly in the command or shell history.
kubectl create secret generic openai-api-key \
  --from-file=token=/path/to/protected/openai-token \
  --namespace=default

# 3. Apply the provider after its referenced Secret exists
kubectl apply -f inference-provider.yaml

# 4. Verify operator generates overlay ConfigMap
kubectl get configmap grid-overlay-example-consumer-gateway -o yaml

# 5. Deploy Praxis AI gateway (separate - not included here)
#    Must reference the generated ConfigMap above
```

## Generated Resources

The AGN Operator will create:

- `ConfigMap/grid-overlay-example-consumer-gateway` - routing overlay for
  Praxis AI
- `Secret/grid-ca-cert` - Grid CA certificate (auto-generated)  
- `Secret/grid-site-cert` - site certificate for this cluster (auto-generated)

## What This Proves

- [PASS] Grid CRDs can be applied
- [PASS] Operator processes resources without errors
- [PASS] RBAC allows Secret/ConfigMap operations
- [PASS] Routing overlay generation works
- [PASS] The supported controller-managed bearer-token reference validates

❌ This does NOT test end-to-end routing (requires Praxis AI gateway deployment)

## Notes

- **Credential**: Replace the example value with a real OpenAI API token
- **Endpoint**: Uses the OpenAI API host (`api.openai.com`)
- **Praxis Gateway**: Must be deployed separately with Grid-compatible configuration
- **No mTLS**: This example uses a bearer token for upstream API
  authentication, not inter-site mTLS
