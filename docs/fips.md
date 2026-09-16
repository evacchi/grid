# FIPS support

For a FIPS build, the security-relevant crypto (the TLS stacks and certificate
identity hashing) must route through the system openssl (dynamically linked
libssl and libcrypto). Pure-Rust crypto (rustls, ring, sha2) and a statically
vendored openssl fall outside the validated boundary.

An opt-in `fips` feature on the operator and overlay-sync crates routes the
TLS client stacks (reqwest, rmcp, kube) through system openssl instead of
rustls:

    cargo build -p operator --no-default-features --features fips

Default builds keep rustls and are unchanged.

The `fips` feature also routes certificate fingerprint hashing (peer identity and
pin matching) through the OpenSSL EVP digest, so no identity hash runs on the
sha2 crate.

Two non-security uses of pure-Rust crypto remain by design and stay outside the
boundary. The overlay envelope content digest is a content-addressing and
revision-equality hash on the sha2 crate in the operator runtime. An overlay's
authenticity comes from the mTLS transport and the trust layer, not from this
digest. Setup-time certificate generation uses rcgen in the environment setup
tooling, not the operator runtime. Neither is identity, authentication, or a
signature.

The binary inherits FIPS mode from the host and does not enable it. A build is
FIPS only when it runs on a host with the OpenSSL FIPS provider active (kernel
`fips=1` and the system crypto policy set to FIPS).
