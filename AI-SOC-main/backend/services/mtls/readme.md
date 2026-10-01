### Start the vault

Need to start vault before running the fastapi application

1. **Docker Compose**: after `vault` is healthy, **`vault-init`** runs once. It **creates the PKI roles** `pki_int/roles/wazuh-manager` and `pki_int/roles/fastapi-service` (so Vault registers `issue/wazuh-manager` and `issue/fastapi-service`), then writes ACL policies from `infra/docker/vault/policies/`. The **`api`** (mTLS) container waits for `vault-init` to finish successfully. **Requires `pki_int` already mounted** (run `utils/vault_setup.sh` once if this is a brand-new Vault with no PKI).

2. **First-time PKI (nothing in Vault yet — `pki_int` missing)** — you do **not** need the Vault CLI on your laptop:

   ```bash
   docker compose --profile setup run --rm vault-pki-bootstrap
   ```

   The script prints **FastAPI Service** `role_id` and `secret_id`. Add them to your repo root **`.env`** as **`vault_role_id`** and **`vault_secret_id`** (see `.env.example`). The `api` (soar-mtls) container loads these via `env_file: .env`.

   Then:

   ```bash
   docker compose run --rm vault-init
   docker compose restart api
   ```

3. **Manual PKI** (Vault CLI on host): `export VAULT_ADDR=http://127.0.0.1:8200` and `VAULT_TOKEN=<same as VAULT_DEV_ROOT_TOKEN in .env>`, then `bash backend/services/mtls/app/utils/vault_setup.sh`. Keep policies aligned with `infra/docker/vault/policies/fastapi-service.hcl`.

#### `invalid role or secret ID` on AppRole login

Your **Role ID** and **Secret ID** from `vault_setup.sh` are the right *shape* (FastAPI block: `6b72…` / `b1d4…`). Common causes:

1. **`vault-init` turned on `bind_secret_id`** for `fastapi-service` (older `ensure-policies.sh`). That can break Secret IDs issued before that change. **Fix:** use the current repo `ensure-policies.sh` (no `bind_secret_id`), then run `docker compose run --rm vault-init`, restart `api`.
2. **Whitespace or quotes** in `.env` — values must be plain UUIDs, no spaces or `"…"` in the value.
3. **Stale Secret ID** — generate a new one with the root token and update `.env`:

   ```bash
   docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=soar-dev-root-token && vault write -field=secret_id -f auth/approle/role/fastapi-service/secret-id'
   ```

   Put the output in `vault_secret_id` and `docker compose restart api`.

#### `permission denied` on `POST .../pki_int/issue/wazuh-manager`

The AppRole token can authenticate but its **policy** does not allow issuing Wazuh certs. Fix:

- Re-apply policies: `docker compose run --rm vault-init` (uses root token `VAULT_DEV_ROOT_TOKEN` / default `soar-dev-root-token`).
- Or run `vault_setup.sh` again (updates the `fastapi-service` policy).
- Ensure `.env` **`vault_role_id` / `vault_secret_id`** belong to the **`fastapi-service`** AppRole (or `wazuh-manager`, which also has `issue/wazuh-manager` in its policy).

#### `route entry not found` / `no handler for route "pki_int/issue/wazuh-manager"`

Vault has `pki_int` but the **named PKI role** was never created, so the issue URL does not exist. Fix:

- **Compose**: `docker compose run --rm vault-init` (creates `pki_int/roles/wazuh-manager` and `fastapi-service` if `pki_int` is mounted), then `docker compose restart api`.
- **Manual**: `vault write pki_int/roles/wazuh-manager ...` as in `utils/vault_setup.sh`, or re-run the full `vault_setup.sh`.

If **`pki_int` is not mounted** at all, `vault-init` exits with an error — run **`docker compose --profile setup run --rm vault-pki-bootstrap`** (or `vault_setup.sh` from the host with the Vault CLI).

4. **Local uvicorn (no Compose)**: run `./utils/vault_setup.sh` once, then from the project root:

```
uvicorn backend.services.mtls.app:app \
  --reload \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-keyfile $(pwd)/backend/services/mtls/app/security/certs/server.key \
  --ssl-certfile $(pwd)/backend/services/mtls/app/security/certs/server.crt \
  --ssl-ca-certs $(pwd)/backend/services/mtls/app/security/certs/ca.crt \
  --ssl-cert-reqs 2
```

- update .env with vault variables (fastapi)

- ngrok cannot pass through the client certificate because it terminates SSL.

```
uvicorn services.ingestion.app:app \
  --reload \
  --host 0.0.0.0 \
  --port 8443 \
  --ssl-keyfile services/ingestion/app/security/certs/server.key \
  --ssl-certfile services/ingestion/app/security/certs/server.crt
```

- ngrok tcp tunnel
- direct vpn.

---

1. start vault
2. add keys in vault_setup
3. start the server

---

### Client certificate validation (enforced)

The ingestion endpoints (e.g. `POST /api/v1/wazuh`) require a **valid client certificate** when:

- `REQUIRE_CLIENT_CERT=true` (default)

Validation happens in two layers:

1. **TLS layer (recommended)**: run uvicorn with `--ssl-ca-certs ... --ssl-cert-reqs 2` so the TLS handshake itself requires and verifies a client cert.
2. **Application layer (always-on)**: FastAPI validates the client certificate **presented by a trusted TLS terminator** via the request header:

- `X-SSL-Client-Cert`: client certificate in PEM form (often URL-escaped by a proxy)

This design supports both:

- **Direct mTLS to uvicorn** (no proxy): you can configure a reverse proxy or ASGI server that forwards the client cert as `X-SSL-Client-Cert`, or extend the app to read it from the ASGI scope if you terminate TLS in-process.
- **mTLS terminated by nginx/traefik**: the proxy does mTLS and forwards the verified client cert to the app in `X-SSL-Client-Cert`.

#### Nginx example (mTLS termination)

Set:

- `ssl_verify_client on;`
- `ssl_client_certificate /path/to/ca.crt;`
- Forward the escaped cert:

```
proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
```

#### Docker Compose (recommended)

With the main `docker-compose.yml`, nginx is the external ingress for mTLS on **port 8443**:

- SIEMs send alerts to: `https://<host>:8443/api/v1/wazuh`
- nginx verifies the client cert using `backend/services/mtls/app/security/certs/ca.crt`
- nginx forwards the verified cert as `X-SSL-Client-Cert` to the upstream mTLS service on the internal network

For security, the mTLS service port is **not** published directly to the host; only nginx exposes 8443.

For local Swagger/testing only, compose may map **`8444:8443`** so you can open `https://localhost:8444/docs` without conflicting with nginx on 8443.

#### What is validated

- Certificate validity window (notBefore / notAfter)
- Certificate **signature** is verified against the trusted CA certs mounted at:
  - `backend/services/mtls/app/security/certs/ca.crt`
  - optionally `backend/services/mtls/app/security/certs/intermediate.cert.pem`
- Client cert **Common Name** must match `TRUSTED_CLIENT_CN_PATTERN` (default `wazuh.*`)

To disable mTLS enforcement for local testing:

- Set `REQUIRE_CLIENT_CERT=false`
