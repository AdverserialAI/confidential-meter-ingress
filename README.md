# Confidential meter ingress

> **Not in the production metering path.** As of 2026-11-24 the production
> proxy ([attest-proxy](https://github.com/AdverserialAI/attest-proxy)
> `v0.1.0-rc.33`) runs with `METER_DELIVERY_MODE: direct-signed`: it signs each
> count-only usage record with a meter key generated inside the confidential
> VM and posts it straight to `https://billing.adverserial.ai` over TLS. No
> mTLS hop and no instance of this service sits in between. The deployed
> composition is documented in
> [confidential-infra `deployed/`](https://github.com/AdverserialAI/confidential-infra/tree/main/deployed).
>
> This repository is the optional alternative. The proxy still implements the
> matching `mtls-ingress` mode (it is the proxy's default when
> `METER_DELIVERY_MODE` is unset), so the service can be put in the path by a
> deployment that wants a separate network-origin check. Do not describe the
> production deployment as using mTLS for metering.

`confidential-meter-ingress` is a small, separately deployable mTLS boundary
between an attested inference proxy and `billing.adverserial.ai`.

It accepts **only** a signed, count-only confidential meter envelope at
`POST /cc/meter`. Mutual TLS is mandatory. It verifies the client certificate
against a dedicated CA, optionally pins the client certificate's SPKI, enforces
TLS 1.3, limits request size, and forwards the unchanged envelope to billing.
It never accepts prompts, completions, API keys, cookies, entitlement tokens,
or an arbitrary upstream URL.

The ingress does **not** replace signature verification. Billing verifies the
proxy's Ed25519 meter JWS after the ingress forwards it. This makes mTLS a
network-origin control and the JWS an end-to-end integrity and idempotency
control.

## Boundary

```text
attested proxy -- TLS 1.3 + client cert --> meter ingress -- HTTPS --> billing
   count-only JWS                             fixed upstream       verifies JWS
```

The ingress must be deployed **outside** the CVM, on a host/load balancer that
preserves TLS to this process. Do not place a TLS-terminating CDN or Heroku
dyno in front of it: this Go process must see and validate the CVM client
certificate itself.

## Configuration

| Variable | Required | Meaning |
|---|---:|---|
| `LISTEN_ADDR` | no | Default `:8443`. |
| `TLS_CERT_FILE` | yes | Server certificate PEM. |
| `TLS_KEY_FILE` | yes | Server private-key PEM. |
| `CLIENT_CA_FILE` | yes | PEM CA that issued the CVM meter-client certificate. |
| `EXPECTED_CLIENT_SPKI_SHA256` | yes | Comma-separated `sha256:<base64url>` pins for the dedicated CVM meter-client certificate. |
| `BILLING_METER_URL` | yes | Exact HTTPS billing URL, ending in `/cc/meter`. |
| `BILLING_INGRESS_SECRET` | yes | Shared random value sent only as `X-Adverserial-Meter-Ingress`. |
| `REQUEST_TIMEOUT_SECONDS` | no | Default `15`, bounded 1–60. |

`BILLING_METER_URL` must be an HTTPS URL without a query, fragment, userinfo,
or non-default path. It is deliberately fixed at startup.

Generate a dedicated private PKI for this one link. Keep the CVM client key
sealed to the CVM. Unlike the proxy's signing keys, which are generated inside
the VM, this client certificate and key are created by the operator and passed
in as sealed configuration. Put the CA public certificate and the ingress server
certificate/key on the ingress host; never share client keys with billing.

## Billing configuration

Set `CC_METER_INGRESS_SHARED_SECRET` to the same high-entropy secret. The
billing endpoint rejects requests that do not present this header, then
still verifies the meter JWS and settles the reservation idempotently.

The same header is what the proxy itself sends in `direct-signed` mode, where
its `METER_INGRESS_SHARED_SECRET` variable holds the value. Despite the name,
in that mode no ingress is involved: the secret is a capability shared between
the proxy and billing.

## Run

```sh
go test ./...
go build ./cmd/meter-ingress
TLS_CERT_FILE=/run/secrets/server.crt \
TLS_KEY_FILE=/run/secrets/server.key \
CLIENT_CA_FILE=/run/secrets/cvm-client-ca.crt \
EXPECTED_CLIENT_SPKI_SHA256='sha256:...' \
BILLING_METER_URL='https://billing.adverserial.ai/cc/meter' \
BILLING_INGRESS_SECRET='...' \
./meter-ingress
```

For a confidential-VM deployment, supply `TLS_CERT_PEM_B64`,
`TLS_KEY_PEM_B64`, and `CLIENT_CA_PEM_B64` together instead of the three file
paths. The process writes them only to a new private ephemeral directory,
then removes the base64 secret variables from its process environment before
loading TLS. The ready-to-deploy Phala CPU-TEE profile is in
[`deploy/phala`](deploy/phala/README.md).

## Operational checks

* Health check: `GET /healthz` returns `204` and has no billing dependency.
* Test mTLS from the CVM using its meter client certificate. A request without
  a client certificate must fail during TLS handshake.
* Verify that a valid signed meter envelope returns `2xx` only after billing
  accepts it; the ingress never converts a billing rejection into success.
* Ensure any edge proxy operates as L4 TCP/SNI pass-through. If it terminates
  TLS, the ingress cannot attest to the client certificate.

Please report security vulnerabilities directly to [security@adverserial.ai](mailto:security@adverserial.ai).

## License

This repository is source-available proprietary software owned by Adverserial
AI LLC. See [`LICENSE`](./LICENSE) and [`LICENSING.md`](./LICENSING.md).
Third-party components retain their own terms.
