# Media Approval Portal v9 — owner auto-approval + My requests

This is a modification of v8 library-specific routing, preserving the same six Maintainerr collections and existing SQLite database.

## New behavior

- Plex server owner: new individual/bulk requests automatically run through the **same** preflight and one-shot Maintainerr membership-confirming approval engine as the admin Approve button. This **schedules real deletion** after the configured Maintainerr delay, currently 1 day. Existing pending/review requests are not auto-approved on startup.
- Shared Plex users: requests remain `pending` and cannot approve, reject, or revoke sessions.
- `My requests` link: server-side authenticated, requester-scoped, 25 requests per page, showing title, status, date and errors. Status `approved` means Maintainerr membership confirmed, not that media has already been deleted.
- The `review` status is retained for ambiguous upstream calls; automatic retries are prohibited.

## Before installing

**Do not deploy without running runtime tests and a new Trivy scan.** The build has been syntax-checked, but not run in a full Docker test environment here.

1. Stop the current portal container and back up `/mnt/user/appdata/media-approval-portal/requests.sqlite3` with its WAL/SHM files if any (or use SQLite backup API while running).
2. Extract ZIP under `/mnt/user/appdata/`, keep this folder's name.
3. Copy existing v8 `.env` to the new folder and verify `MIN_DELETE_DAYS=1` and all six collection ID settings. Never publish `.env`.
4. Build, test, scan:

```bash
cd /mnt/user/appdata/media-approval-portal-v9-owner-auto-history
docker build --pull --no-cache -f Dockerfile.alpine -t local/media-approval-portal:v9-owner-history .
docker run --rm --entrypoint python local/media-approval-portal:v9-owner-history /app/test_runtime.py
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro aquasec/trivy:latest image --scanners vuln --severity HIGH,CRITICAL --exit-code 1 local/media-approval-portal:v9-owner-history
```

5. After all tests pass, edit the Unraid Docker container: image `local/media-approval-portal:v9-owner-history`; change just the `--env-file` path to `/mnt/user/appdata/media-approval-portal-v9-owner-auto-history/.env`. Preserve the rest of the security flags, port 8085:8080, `media` network and `/data` mapping.
6. Log in with your Plex account and inspect **My requests**. For auto-approval live testing, use a title you intentionally want to delete (Maintainerr deletion occurs after ~1 day); verify the correct library-specific collection and status before attempting further requests.

**Existing v8 library mapping:** Movies=1, TV Shows=2, Kids Movies=3, Anime Movies=4, Kids TV Shows=5, Anime TV Shows=6. No database migration is needed. You must confirm these collections still match the intended Plex libraries.

Note: The review workflow is not a guarantee of deletion; follow Maintainerr/Radarr/Plex logs for final outcomes.


## Additional security safeguards

* **Maintainerr library validation:** Preflight compares collection `libraryId` with the Plex media section ID. Mismatches are rejected before any deletion API call.
* **Duplicate protection:** SQLite partial unique index prevents a second active or approved request for the same Plex media ID, even between concurrent workers. Startup fails safely if existing duplicates must be resolved.
* **Rate limiting:** In-app browser-nonce throttle is not an internet-wide protection. Cloudflare edge rules and origin isolation are required (see [SECURITY.md](SECURITY.md)).
* **Deployment:** The public Compose example binds only loopback; customize it safely for your network. Your existing Unraid port mapping and .env are not modified by this source update.

**Verification status:** This security-hardening patch is not audited or verified on a live deployment. Build the image, run tests and Trivy, and inspect Maintainerr's `libraryId` before switching a production container.

## Security verification

**Last verified: November 15, 2026**

| Security check | Result |
|---|---|
| Automated regression and security tests | **26/26 passed** |
| Trivy HIGH vulnerabilities | **0 detected** |
| Trivy CRITICAL vulnerabilities | **0 detected** |
| Gitleaks secret scanning | **0 findings** |
| SQLite duplicate-request protection | **Passed** |
| Cloudflare Plex login rate limiting | **Active** |
| External direct-origin IPv4 test | **Filtered** |

The Trivy results apply to the tested Docker image
`local/media-approval-portal:security-hardening`.

See [Detailed Security Testing Results](SECURITY_TESTING.md)
for test coverage, scan evidence, and limitations.

These checks do not constitute an independent penetration test
or guarantee the absence of vulnerabilities.
