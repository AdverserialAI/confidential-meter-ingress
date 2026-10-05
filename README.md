# Confidential meter ingress

`confidential-meter-ingress` is the small, separately deployable mTLS boundary
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
| `EXPECTED_CLIENT_SPKI_SHA256` | no | Comma-separated `sha256:<base64url>` pins for the CVM client certificate. Pinning is recommended. |
| `BILLING_METER_URL` | yes | Exact HTTPS billing URL, ending in `/cc/meter`. |
| `BILLING_INGRESS_SECRET` | yes | Shared random value sent only as `X-Adverserial-Meter-Ingress`. |
| `REQUEST_TIMEOUT_SECONDS` | no | Default `15`, bounded 1–60. |

`BILLING_METER_URL` must be an HTTPS URL without a query, fragment, userinfo,
or non-default path. It is deliberately fixed at startup.

Generate a dedicated private PKI for this one link. Keep the CVM client key
sealed to the CVM. Put the CA public certificate and the ingress server
certificate/key on the ingress host; never share client keys with billing.

## Billing configuration

Set `CC_METER_INGRESS_SHARED_SECRET` to the same high-entropy secret. The
billing endpoint rejects direct requests that do not present this header, then
still verifies the meter JWS and settles the reservation idempotently.

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
paths. The process writes them only to a private ephemeral directory before
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
