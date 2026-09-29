# Praxis Configuration

This directory owns the consumer-gateway and provider-gateway Praxis
configuration used by the distributed token-quota topology.

Consumer configuration must contain the AGN-managed routing overlay mount and
must not contain provider credentials. Provider configuration must enforce
mTLS peer identity, provider-route authorization, and final-hop credential
injection before forwarding to a private inference endpoint.

The west Valkey consumers intentionally share the same limiter namespace and
Alice rule. The single-principal Basic Auth gate makes this Alice's distributed
qualification budget without relying on a client-supplied identity header.

Site-specific addresses and identities are rendered from structured inputs.
