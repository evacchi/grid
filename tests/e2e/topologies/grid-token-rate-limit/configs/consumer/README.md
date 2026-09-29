# Consumer Gateway

`praxis-valkey-a.yaml` and `praxis-valkey-b.yaml` are independently addressable
west consumers backed by the same Valkey namespace and Alice rule. Their filter
order is intentional:

```text
Basic Auth -> model extraction -> token reservation -> AGN routing
           -> provider request -> token counting -> quota settlement
```

Response hooks execute in reverse order, so `token_count` publishes actual
usage before `token_rate_limit` reconciles the reservation. This topology has
no in-memory fallback consumer: both deployed consumers must use shared Valkey
state.
