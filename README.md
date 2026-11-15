# Media Approval Portal

**A self-hosted, Plex-powered deletion-request and approval portal for shared media libraries.**

Media Approval Portal gives people who use your Plex server a straightforward way to suggest movies and TV shows for removal—without granting them access to your filesystem, Radarr, Sonarr, or Maintainerr. Users sign in with Plex, browse eligible libraries, select titles, and track their requests. The Plex server owner makes the final decision; their own requests can be approved automatically using the same safety checks.

Approved titles are handed to **Maintainerr** for scheduled deletion. The portal does not delete files itself.

> **Warning:** Approving a request can initiate permanent media deletion after the configured delay. Test only with titles you actually want removed.

## How it works

```text
Plex account → Plex SSO → Verify access to your Plex server
                                 |
                        Browse eligible libraries
                                 |
                        Select movie(s) / show(s)
                                 |
                     +-----------+-----------+
                     |                       |
                Shared user              Server owner
                     |                       |
               Pending review          Auto-approval
                     |                       |
                Owner approves               |
                     +-----------+-----------+
                                 |
                       Security / library checks
                                 |
                   Correct Maintainerr collection
                                 |
                    Scheduled downstream deletion
```

### Features

- **Plex sign-in:** No separate portal account or password. Plex server membership is checked before access is granted.
- **Owner-controlled requests:** Shared Plex users can submit requests, but cannot approve, reject, or manage portal sessions.
- **Owner auto-approval:** The verified Plex owner’s individual and bulk requests use the same validation and approval process as manually approved requests.
- **Media discovery:** Browse Plex libraries, search titles, and select multiple movies or TV shows.
- **Library-aware routing:** Send approved content to a different Maintainerr collection for each configured Plex library. Supports standard, kids, and anime movie/TV libraries.
- **Private request history:** Users can see their own requests and statuses on **My requests**, with pagination.
- **Conflict protection:** SQLite prevents concurrent duplicate active or approved requests for the same Plex media ID.
- **Fail-safe handoff:** A timeout or uncertain Maintainerr result becomes `review`, never an automatic retry.
- **Self-hosted deployment:** Python/Flask application with SQLite storage, packaged for Docker and suitable for Unraid.

## Request statuses

| Status | Meaning |
| --- | --- |
| `pending` | Waiting for a decision from the server owner |
| `approved` | Maintainerr collection membership was confirmed; deletion may still be scheduled for later |
| `rejected` | The owner declined the request; the title may be requested again |
| `review` | The outcome of a Maintainerr submission is uncertain and requires manual investigation before retrying |

## Requirements

- Docker host (Unraid or another Linux Docker environment)
- Plex Media Server and a Plex owner account with the permissions needed by the portal
- Maintainerr configured to manage the relevant libraries and perform the intended deletion actions
- Radarr and/or Sonarr where applicable to your deletion workflow
- HTTPS reverse proxy for internet access, with edge rate limiting and origin protection
- Persistent storage for the portal's SQLite database

The sample `.env.example` and `compose.yaml` are **templates**. Use your own addresses, credentials, Plex libraries, and Maintainerr collection IDs. Do not publish `.env` or the SQLite database.

## Quick start

1. Clone the repository and create a private environment file:

   ```bash
   git clone https://github.com/tbutz12/MediaApprovalPortal.git
   cd MediaApprovalPortal
   cp .env.example .env
   ```

2. Configure `.env` using the documented variables and your own credentials. In particular, set the Plex owner/server settings, Maintainerr URL, the collection mappings, session secret, and deletion-delay policy. **Do not use example secrets or public URLs without reviewing them.**
3. Create the required Maintainerr collections. Each must target the correct Plex library and media type, have the intended deletion action, and satisfy `MIN_DELETE_DAYS`. Turn off automated rule selection if only explicit, owner-approved submissions should be included.
4. Build and validate the image:

   ```bash
   docker build --pull --no-cache -f Dockerfile.alpine \
     -t local/media-approval-portal:security-hardening .

   docker run --rm --entrypoint python \
     local/media-approval-portal:security-hardening /app/test_runtime.py
   ```

5. Deploy with persistent `/data` storage and the private `.env` file. On Unraid, you can use your existing Docker template, mapping the application container port `8080` to a suitable local host port. Avoid forwarding that port directly from WAN. Run behind HTTPS and configure edge protections **before** opening access to other users.
6. Sign in as the Plex owner; validate library browsing, requester/owner roles, collection mapping, and request history before authorizing real deletions.

Refer to [SECURITY.md](SECURITY.md) for the public-facing deployment boundary. The example Compose file is not a substitute for reviewing your own Docker and reverse-proxy settings.

## Maintainerr collection mapping

The portal supports these library-specific environment variables. Collection IDs are **instance-specific**; the numbers shown are illustrative only.

| Plex library | Environment variable | Example ID |
| --- | --- | --- |
| Movies | `MOVIE_COLLECTION_ID` | `1` |
| TV Shows | `SHOW_COLLECTION_ID` | `2` |
| Kids Movies | `KIDS_MOVIE_COLLECTION_ID` | `3` |
| Anime Movies | `ANIME_MOVIE_COLLECTION_ID` | `4` |
| Kids TV Shows | `KIDS_SHOW_COLLECTION_ID` | `5` |
| Anime TV Shows | `ANIME_SHOW_COLLECTION_ID` | `6` |

Before a deletion handoff, the portal validates the item's actual Plex library against Maintainerr's collection `libraryId`, along with its type, action, active status, and configured delay. A mismatch fails closed. A one-day minimum can be explicitly configured with `MIN_DELETE_DAYS=1`; choose a delay appropriate to your installation.

## Security verification

**Operator-reported verification date: November 15, 2026.** The results below describe the tested deployment and image, not a blanket guarantee for every installation or future rebuild.

| Check | Recorded result |
| --- | --- |
| Automated security and regression tests | **26 / 26 passed** |
| Trivy HIGH findings | **0 detected** |
| Trivy CRITICAL findings | **0 detected** |
| Gitleaks Git history scan | **0 findings**, 4 commits scanned |
| Gitleaks working-directory scan | **0 findings** |
| SQLite duplicate-active-request check | **Passed** |
| Cloudflare Plex login rate-limiting rule | **Active** in operator's dashboard |
| Direct-origin TCP/443 check from one external scanner | **Filtered** |

**Trivy scope:** Docker image `local/media-approval-portal:security-hardening`, Alpine 3.24.4 and installed Python packages, with the vulnerability DB updated for the November 15, 2026 scan. The runtime regression tests use mocked upstream services for many checks; they do not establish end-to-end deletion correctness.

To reproduce the main checks on your own image:

```bash
docker run --rm --entrypoint python \
  local/media-approval-portal:security-hardening /app/test_runtime.py

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  aquasec/trivy:latest image --scanners vuln \
  --severity HIGH,CRITICAL --exit-code 1 \
  local/media-approval-portal:security-hardening

gitleaks git . --redact
gitleaks dir . --redact
```

For the individual test names, results, threat-model limitations, and reproducibility details, see [**Security Testing Report**](SECURITY_TESTING.md).

**Security limitations:** No independent penetration test has been conducted. The reported external port test only covered one IPv4 vantage point; IPv6 and other ports require separate verification. The in-app anonymous Plex PIN throttle is browser-bound, so a properly configured edge rate limit is required for public access. A clean vulnerability/secret scan does not prove the application has no logic flaws or future vulnerabilities.

## Deployment security

- Keep the Plex token, encryption/session keys, and runtime database out of Git.
- Restrict public traffic to your trusted reverse proxy or a tunnel; do not expose the portal's application port or Unraid/NPM administration ports to WAN.
- Use HTTPS, rate-limit `POST /auth/plex/start`, and verify origin restrictions independently.
- Preserve least-privilege Docker settings where supported: non-root execution, read-only filesystem, dropped capabilities, `no-new-privileges`, PID limits, and temporary writable storage.
- Verify shared, owner, and unshared Plex account behavior in your own environment.
- Inspect Maintainerr membership before reconciling `review` requests; never retry ambiguous destructive operations blindly.

See [SECURITY.md](SECURITY.md) for deployment safeguards and private vulnerability reporting.

## Project scope

The portal is a **request-and-approval layer**. Maintainerr and connected media management services determine when and how approved items are ultimately removed. `approved` confirms the upstream handoff, **not** that Radarr/Sonarr deleted files, Plex refreshed its library, or a request-management app updated its records. Verify those outcomes independently.

## Contributing

Bug reports and improvements are welcome. Avoid publishing API credentials, Plex tokens, private hostnames, real media deletion logs, or exploitable security details in public issues. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md).
