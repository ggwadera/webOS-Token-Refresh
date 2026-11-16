# Hardened LAN deployment: webOS Token Refresher

This package starts from upstream commit `2d5aa799319c3142dd0af5b5d36eca32bf05d51d` (2026-10-14) of [LucifersCircle/webOS-Token-Refresh](https://github.com/LucifersCircle/webOS-Token-Refresh). It preserves the project's GPL-3.0 license. The Docker image is built locally from the included source; it does not pull the upstream `latest` image.

## What the app does

The web form accepts 64-character hexadecimal tokens. It stores a Fernet-encrypted token and a SHA-256 digest in SQLite. The worker decrypts each stored token and calls LG's `ResetDevModeSession.dev` endpoint over HTTPS using `sessionToken` as a query parameter. The upstream endpoint's interface requires that query parameter; this package cannot prevent LG or an intervening TLS-terminating service from seeing it. The worker never logs the URL, token, request exception, or response body.

The package adds reverse-proxy authentication and a LAN CIDR check, CSRF tokens for browser form posts, request-size and token-count limits, safe error responses, secure response headers, timeouts, bounded worker concurrency, read-only worker database access, split container networks, pinned Python dependencies, persistent storage, and container restrictions. The app itself has no login; its network is reachable only by the authenticated Caddy proxy. The JSON API is protected by that same proxy.

## Requirements

- Linux host with Docker Engine and the Docker Compose plugin.
- A static/reserved LAN IPv4 address on that host and a LAN DNS or hosts entry.
- `python3` and `openssl` for secret generation; `age` for encrypted backups.
- A firewall that allows TCP 8443 only from the trusted LAN. Do not forward this port from the internet.

## Install

1. Copy this directory to the Linux host. Keep the source in a private directory and preserve the included files. The deployment does not use your LG token during installation.
2. Reserve the Linux host's LAN address in your router. Choose a local hostname, for example `webos-refresh.home.arpa`, and point it to that address in your router's DNS or on each client.
3. Copy `.env.example` to `.env` and edit `LAN_BIND_IP`, `LAN_CIDR`, and `APP_HOST`. Use your actual subnet in CIDR notation. Set a unique `CADDY_USER`.
4. Generate the two encryption/session secrets:

   ```sh
   ./prepare-secrets.sh
   sudo chown 10001:10001 secrets/encryption_key secrets/flask_secret
   ```

   The files are mode `0400`. Back up `secrets/encryption_key` securely and separately; losing it makes the stored tokens unrecoverable. Keep `flask_secret` private too. Do not commit `.env` or files in `secrets/`.

5. Generate a strong proxy password, save it in your password manager, and create its bcrypt hash:

   ```sh
   docker run --rm -it caddy:2.10.2-alpine caddy hash-password
   ```

   Put the username and resulting hash in `.env` as `CADDY_USER` and `CADDY_PASSWORD_HASH`. Keep the hash inside single quotes because it contains `$` characters. Do not use the sample hash.

6. Allow TCP 8443 from the trusted LAN only in the Linux firewall. For UFW, replace both example addresses:

   ```sh
   sudo ufw allow from 192.168.1.0/24 to 192.168.1.20 port 8443 proto tcp
   ```

   Also verify the router has no port-forwarding rule for 8443. The compose port binds only to `LAN_BIND_IP`; Caddy independently rejects source addresses outside `LAN_CIDR`.

7. Validate and start:

   ```sh
   docker compose config
   docker compose up -d --build
   docker compose ps
   ```

   Open `https://webos-refresh.home.arpa:8443` (using your chosen host name). Caddy creates a private local CA, so browsers will initially warn that the certificate is not trusted. For a trusted connection, copy Caddy's root certificate from the host and install it as a trusted root on the LAN devices that will use the app:

   ```sh
   docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```

   Treat the root certificate as a CA trust anchor: anyone who obtains its private key can impersonate this local service. Only distribute the public `root.crt`; never copy Caddy's CA private key. If you do not install the certificate, the browser warning is expected and credentials still travel over encrypted TLS, but users have weaker server identity verification.

The web app listens only inside Docker. Do not publish its port directly. Caddy Basic Auth is required for both browser and API access. Keep the proxy password strong; Basic Auth is not rate limited. The LAN boundary and host firewall are part of the security model.

## Backups and restore

Install `age` on the Linux host. Create an age key pair and keep the private key offline or in a separate secure location. Set `AGE_RECIPIENT` to the public recipient string, then run:

```sh
AGE_RECIPIENT='age1...' ./backup.sh
```

The script uses SQLite's online backup API, encrypts the snapshot with age, and deletes the temporary plaintext snapshot. Copy `.age` backups off the host. Retain the age private key and `secrets/encryption_key` separately; both are needed to recover token data. The database already encrypts tokens, but backups are encrypted again to protect metadata and provide defense in depth.

To restore, keep the matching `secrets/encryption_key` in place and run:

```sh
AGE_IDENTITY=/secure/path/age-private-key.txt ./restore.sh backups/keys-YYYYMMDDTHHMMSSZ.db.age
```

The script decrypts to a mode-restricted temporary file, stops the app and worker, checks SQLite integrity, replaces the database while preserving owner `10001:10001`, and restarts the services. Validate restores periodically on an isolated copy.

## Operations

- Change the refresh interval with `SCRIPT_INTERVAL` in `.env` (seconds; minimum 300), then run `docker compose up -d`.
- Check logs with `docker compose logs --tail=100 app worker proxy`. The app and worker avoid token values and request URLs in their logs. Caddy's access logging is not enabled.
- Update dependencies deliberately: change pinned versions, rebuild, and review the upstream diff before upgrading. The current source base is identified above; this package does not track upstream automatically.
- To remove a stored token, use the browser form over the authenticated HTTPS URL. The API remains available behind Caddy for clients that support Basic Auth; send the token in a POST body, never a URL.
- Up to 1,000 tokens can be stored. The worker processes at most four requests concurrently and uses 5-second connect and 15-second read timeouts.

## Security notes and remaining risks

- LG's refresh API requires the token in the HTTPS query string. TLS protects the connection in transit, but the URL is exposed to LG and could be recorded by a TLS-terminating network service. This package suppresses request URL logging locally and disables redirects.
- Caddy's local certificate authority is private to this deployment. Install its public root only on trusted LAN clients and protect the Caddy data volume, which holds the CA private key.
- The worker must make outbound HTTPS requests to LG. The app and proxy do not have outbound network access through the configured Docker networks.
- SQLite is suitable for this small single-host workload. Do not put the database volume on a network filesystem. Back up consistently and retain the matching Fernet key.
- There is no account management, password reset, or per-user audit. Anyone who learns the proxy credentials and can reach the LAN URL can add, refresh, or remove tokens.
- Docker Compose file-backed secrets are local files, not a centralized secret manager. Protect the host, backups, `.env`, Docker daemon, and volume. Root on the Linux host can access all container data.
- The LG API's current response semantics are not validated by this tool; the worker logs only the HTTP status and does not interpret whether a refresh succeeded.
- A compromise of the Linux host, Docker daemon, Caddy CA private key, or Fernet key can expose stored tokens. Keep the host patched and physically/network secured.

## Checks

Run the Python regression checks in an environment with dependencies installed:

```sh
python3 -m unittest discover -s tests -v
```

The tests cover the read-only status API contract, add/remove behavior, CSRF rejection for browser posts, safe API errors, outbound timeouts, and suppression of token-bearing URLs from worker logs. `docker compose config` validates Compose interpolation and structure. Before installing, also verify the LAN URL is unreachable from outside the trusted subnet and that the app's port 5000 is not published.
