# Dedicated Logical Edge Gateway Topology

Two consumer clusters and two provider clusters. Consumer clusters run only
Praxis consumer gateways; provider clusters run Praxis provider gateways
alongside inference backends.

```text
east-consumer                       west-consumer
  AGN Operator                        AGN Operator
  Praxis consumer gateway             Praxis consumer gateway
           |                                   |
           +--------- AGN selection -----------+
                       |             |
                       v             v
east-provider                       west-provider
  AGN Operator                        AGN Operator
  Praxis provider gateway             Praxis provider gateway
  inference backend                   inference backend
```

## Values Files

- `values/east-consumer-operator.yaml` -- AGN Operator for the east consumer site
- `values/east-consumer-gateway.yaml` -- Praxis consumer gateway
- `values/west-consumer-operator.yaml` -- AGN Operator for the west consumer site
- `values/west-consumer-gateway.yaml` -- Praxis consumer gateway
- `values/east-provider-operator.yaml` -- AGN Operator for the east provider site
- `values/east-provider-gateway.yaml` -- Praxis provider gateway
- `values/west-provider-operator.yaml` -- AGN Operator for the west provider site
- `values/west-provider-gateway.yaml` -- Praxis provider gateway

## Security

- Provider credentials are mounted only in provider gateway Deployments.
- Consumer gateways receive routing overlays; they do not hold provider credentials.
- mTLS between consumer and provider gateways is configured via TLS Secrets.
