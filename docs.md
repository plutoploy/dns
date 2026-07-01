# ACME DNS-01 Domain Verifier

A Go-based HTTP service that automates SSL/TLS certificate issuance via the
[ACME](https://datatracker.ietf.org/doc/html/rfc8555) protocol using **DNS-01
challenges**. It uses the [lego](https://github.com/go-acme/lego) library under
the hood and exposes a REST API for registering ACME accounts, starting domain
verifications, and completing them.

## How It Works (Conceptual)

Unlike traditional ACME clients that manipulate DNS records directly (e.g. via
API calls to Route53, Cloudflare, etc.), this project takes a **manual DNS
provider** approach:

1. An ACME **order** is created for a domain and the CA issues a DNS-01
   challenge (a TXT record value).
2. The challenge details are saved to an **SQLite database** and the ACME
   goroutine **blocks**, waiting for a signal.
3. An external agent (DNS server, script, or human) reads the challenge from
   the DB and creates the required `_acme-challenge.<domain>` TXT record.
4. The caller hits the **complete** endpoint, which signals the blocked
   goroutine to unblock and tells the ACME CA to validate the record.
5. If validation passes, the certificate is obtained and returned.

This decouples DNS record manipulation from the ACME client logic, making it
suitable for custom or air-gapped DNS systems.

## Architecture

```
┌──────────────────────┐     ┌───────────────────────────────────┐
│   External Agent     │     │         ACME Verifier (API)        │
│   (DNS operator)     │     │                                   │
│                      │     │  ┌─────────┐   ┌───────────────┐  │
│  1. Reads challenge  │────▶│  │  Gin    │──▶│   Verifier    │  │
│     from DB          │     │  │  HTTP   │   │  (lego ACME)  │  │
│                      │     │  │  Routes │   └───────┬───────┘  │
│  2. Creates TXT      │     │  └─────────┘           │          │
│     record           │     │                        │          │
│                      │     │  ┌─────────────────────▼──────┐   │
│  3. Calls /acme/check│────▶│  │    ManualDNSProvider       │  │
│                      │     │  │  (blocks until confirmed)  │  │
└──────────────────────┘     │  └────────────────────────────┘  │
                              │                                   │
                              │  ┌────────────────────────────┐   │
                              │  │   SQLite Store (acme.db)   │   │
                              │  │   - pending challenges     │   │
                              │  └────────────────────────────┘   │
                              └───────────────────────────────────┘
```

## API Endpoints

All ACME routes are mounted under the `/acme` prefix.

### `POST /acme/register`

Register an ACME account with the Certificate Authority.

**Request body** (optional):
```json
{
  "key_type": "EC256"
}
```

Valid `key_type` values:
- `EC256` — ECDSA P-256 (default)
- `RSA4096` — RSA 4096-bit

**Response `200 OK`**:
```json
{
  "email": "admin@example.com",
  "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
  "ca": "https://acme-v02.api.letsencrypt.org/directory"
}
```

### `POST /acme/verify`

Start a DNS-01 challenge for a domain. Returns the TXT record details that must
be provisioned before calling `/acme/check`.

**Request body**:
```json
{
  "domain": "example.com"
}
```

**Response `200 OK`**:
```json
{
  "domain": "example.com",
  "fqdn": "_acme-challenge.example.com.",
  "value": "abc123...xyz",
  "token": "...",
  "status": "pending"
}
```

The caller must create a TXT record at `fqdn` with the given `value`. This
endpoint blocks until the ACME CA has issued the challenge and the provider has
stored it — typically under one second, but can take longer if the CA is slow.

### `POST /acme/check`

Signal that the DNS TXT record has been set and complete the ACME verification.

**Request body**:
```json
{
  "domain": "example.com"
}
```

**Response `200 OK` (success)**:
```json
{
  "domain": "example.com",
  "status": "valid"
}
```

**Response `200 OK` (failure)**:
```json
{
  "domain": "example.com",
  "status": "invalid",
  "error": "..."
}
```

This call **blocks** until the ACME CA validates the challenge (typically
5–30 seconds). If validation fails, the `status` is `"invalid"` and the
`error` field describes why.

### `GET /acme/status/:domain`

Get the current status of a pending verification.

**Response `200 OK`**:
```json
{
  "domain": "example.com",
  "status": "pending"
}
```

Possible statuses: `"pending"`, `"not_found"`.

### `GET /acme/account`

Get the currently registered ACME account info.

**Response `200 OK`**:
```json
{
  "email": "admin@example.com",
  "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123456",
  "ca": "https://acme-v02.api.letsencrypt.org/directory"
}
```

### `GET /health`

Health-check endpoint (not under `/acme`).

**Response `200 OK`**:
```json
{
  "message": "ok"
}
```

## Configuration

All configuration is via environment variables:

| Variable             | Default                        | Description                                      |
|----------------------|--------------------------------|--------------------------------------------------|
| `ACME_DIRECTORY_URL` | `https://acme-v02.api.letsencrypt.org/directory` | ACME CA directory URL (use `https://acme-staging-v02.api.letsencrypt.org/directory` for staging) |
| `ACME_ACCOUNT_EMAIL` | —                              | Email for ACME account registration **(required)** |
| `ACME_DB`            | `./acme.db`                    | Path to the SQLite database for challenge storage |
| `LISTEN_ADDR`        | `:8080`                        | Address and port to bind the HTTP server          |

**Recommended flow for testing:**
1. Set `ACME_DIRECTORY_URL` to the Let's Encrypt **staging** environment.
2. Register, verify, and confirm the flow works.
3. Switch to the production directory URL for real certificates.

## SQLite Database Schema

The `challenges` table stores pending DNS-01 challenge tokens:

```sql
CREATE TABLE IF NOT EXISTS challenges (
    domain    TEXT PRIMARY KEY,
    fqdn      TEXT NOT NULL,
    value     TEXT NOT NULL,
    token     TEXT NOT NULL,
    key_auth  TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
```

## Typical Usage Flow

```bash
# 1. Start the server
export ACME_ACCOUNT_EMAIL="admin@example.com"
export ACME_DIRECTORY_URL="https://acme-staging-v02.api.letsencrypt.org/directory"
go run .

# 2. Register an ACME account
curl -X POST http://localhost:8080/acme/register

# 3. Start domain verification
curl -X POST http://localhost:8080/acme/verify \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'
# → Returns fqdn and value for the TXT record

# 4. Create the TXT record at your DNS provider
#    _acme-challenge.example.com.  TXT  "the-value-from-step-3"

# 5. Complete verification
curl -X POST http://localhost:8080/acme/check \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com"}'
# → {"domain":"example.com","status":"valid"}
```

## Project Structure

```
.
├── main.go            # Entry point, Gin server, route mounting
├── acme/
│   ├── acme.go        # Core ACME logic (Verifier, ManualDNSProvider, Store)
│   └── protocol.go    # HTTP handlers and route setup
├── acme.db            # SQLite database (auto-created, git-ignored)
├── go.mod
├── go.sum
└── mise.toml          # Development tool versions (go, golangci-lint)
```

## Package: `acme`

### Types

| Type                | Description                                              |
|---------------------|----------------------------------------------------------|
| `AcmeUser`          | Implements `registration.User` for lego. Holds email, private key, and ACME registration. |
| `PendingChallenge`  | Describes a DNS-01 challenge: domain, FQDN, TXT value, token, key authorization. |
| `Store`             | SQLite-backed persistence for challenges. Methods: `SaveChallenge`, `RemoveChallenge`, `GetChallenge`. |
| `ManualDNSProvider` | DNS-01 provider that stores challenge info and blocks `Present()` until `Confirm()` is called. |
| `Verifier`          | Main orchestrator. Manages ACME registration, domain verification lifecycle, and pending state. |
| `VerifierConfig`    | Configuration: DirectoryURL, Email, KeyType, DSN, HTTPClient. |
| `AccountInfo`       | Returned after registration: Email, URI, CA.             |
| `DomainChallenge`   | Challenge info returned from `StartVerification`: Domain, FQDN, Value, Token, Status. |
| `VerificationResult`| Outcome of `CompleteVerification`: Domain, Status, Error. |

### Key Methods (Verifier)

- `NewVerifier(cfg VerifierConfig) *Verifier` — Create a new verifier (account is not registered yet).
- `(*Verifier).RegisterAccount(ctx) (*AccountInfo, error)` — Register or resolve an ACME account.
- `(*Verifier).Account() *AccountInfo` — Return current account info (nil before registration).
- `(*Verifier).StartVerification(ctx, domain) (*DomainChallenge, error)` — Start DNS-01 challenge; returns TXT record details.
- `(*Verifier).CompleteVerification(ctx, domain) (*VerificationResult, error)` — Confirm TXT record set and finish verification.
- `(*Verifier).VerificationStatus(domain) string` — Check if a verification is pending (`"pending"` or `""`).
- `(*Verifier).CloseStore() error` — Close the SQLite store on shutdown.

### Key Methods (ManualDNSProvider)

- `Present(ctx, domain, token, keyAuth) error` — Stores the challenge, persists to SQLite, and blocks.
- `CleanUp(ctx, domain, token, keyAuth) error` — Removes pending state and DB record.
- `Pending() *PendingChallenge` — Returns the current pending challenge (nil if none).
- `Confirm()` — Unblocks `Present()` so the ACME flow continues.

## Dependencies

- **`github.com/gin-gonic/gin`** — HTTP router/framework.
- **`github.com/go-acme/lego/v5`** — ACME client library.
- **`modernc.org/sqlite`** — Pure-Go SQLite driver (no CGo required).
- **Go 1.26+** — This project uses modern Go features.

## Notes

- The account private key is **generated fresh in memory** on each
  `RegisterAccount` call. In production you should persist it (lego's
  `registration.Register` resolves existing accounts via the ACME server,
  but the key must match).
- The `fqdn` returned by `/acme/verify` includes a trailing dot
  (fully-qualified domain name), e.g. `_acme-challenge.example.com.`.
- The server does **not** set DNS records itself — that responsibility lies
  with an external agent (script, DNS operator, or automation).
- For production use, consider wrapping the `/acme/verify` → external
  DNS-set → `/acme/check` flow in an automated pipeline.
