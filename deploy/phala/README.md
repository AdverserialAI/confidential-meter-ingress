# Phala CPU-TEE deployment

Deploy this service as its own small Phala CPU confidential VM, named
`cc-meter-ingress`. It is intentionally separate from the GPU CVM and from
Heroku billing: the ingress validates the GPU CVM's TLS client certificate
before forwarding a count-only signed envelope to the fixed billing endpoint.

## Release first

The GitHub release workflow publishes an immutable GHCR digest. Put that exact
digest in `METER_INGRESS_IMAGE`; never use `latest` or a mutable tag.

Generate the private mTLS material from the confidential-infra repository. The
CVM receives only its client certificate/key and the server CA. This VM gets
the server certificate/key and the client CA. Base64-encode the PEM files into
an untracked local environment file using standard base64 (`base64 < file`).

## Deploy

1. In Phala Cloud, choose **Deploy → CPU TEE**, give it the name
   `cc-meter-ingress`, choose a current production OS image, and use a small
   instance (1 vCPU / 2 GB is sufficient for this narrow Go service).
2. Paste [docker-compose.yml](docker-compose.yml), add the exact variables
   from `.env.example` through Phala's encrypted-secrets panel, and deploy.
   The process materializes the three PEM values only in its private `/tmp`
   directory with `0700`/`0600` permissions at startup.
3. Confirm `GET /healthz` over the TLS pass-through hostname returns `204`.
   A connection without the dedicated GPU-CVM client certificate must fail the
   TLS handshake.
4. Create a Gandi CNAME for `meter-ingress.adverserial.ai` that targets the
   resulting Phala `<app-id>-8443s.dstack-…phala.network` hostname. The `s`
   suffix is essential: it preserves TLS to this process.
5. Set the GPU CVM's `METER_URL=https://meter-ingress.adverserial.ai` and
   publish the corresponding mTLS server CA in its sealed bundle. Do this only
   as part of the one reviewed GPU-CVM update.

The meter service carries no prompts, completions, API keys, session cookies,
or entitlement tokens. It receives an idempotent, signed token-count record
only.
