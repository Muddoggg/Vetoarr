# Media Approval Portal

**Plex SSO-powered, owner-controlled media cleanup for Unraid.** Shared Plex users can request the removal of movies and shows; the verified server owner can approve their requests. Owner-submitted requests use the same preflight checks for automatic approval. Approved items are handed to Maintainerr for scheduled removal.

> **Security status:** The documented test suite contains **22 regression/security checks**. Earlier Unraid testing reported a clean HIGH/CRITICAL Trivy scan for the **v7-fixed** image; a separate clean scan was also reported for **v6**. **Those results do not certify the current v9 image.** Run the full suite and rescan whenever the source or base image changes. This project has **not** undergone an independent penetration test or comprehensive security audit.

## Security testing and vulnerability results

### At-a-glance results

| Verification | Evidence / reported result | Scope |
| --- | --- | --- |
| Security and functional regression suite | **22 test cases implemented** in [`test_runtime.py`](test_runtime.py); execute the command below for a current pass/fail result | v9 source, using mocked Plex/Maintainerr APIs |
| Trivy vulnerability scanning | **0 HIGH / 0 CRITICAL reported** by the operator for `local/media-approval-portal:v7-fixed`; earlier v6 Alpine image also reported 0/0 | Previous image builds, **not a verified v9 scan result** |
| Container build and start | v7 Gunicorn startup confirmed from Unraid logs; v9 owner auto-approval and collection routing were subsequently exercised by the operator | Live observations, not a full end-to-end security test |
| TLS at public hostname | TLS 1.3 and certificate verification succeeded in an Unraid `curl -Iv` check on 2026-11-15 | External HTTPS connection; does not validate the complete browser resource chain |
| Third-party penetration test | **Not performed** | No certification or guarantee of vulnerability-free operation |

**Interpretation:** "0 HIGH / 0 CRITICAL" means the vulnerability scanner found no issues of those severities in the **specific image scanned at that time**, using its available database. It does not mean zero vulnerabilities in the Python application, authentication flow, dependencies in the future, or infrastructure. The v9 suite covers critical expected behavior, but much of it mocks upstream services and cannot prove production behavior by itself.

### Security regression coverage (22 tests)

| Area | What is checked |
| --- | --- |
| Authentication | Anonymous access redirects to login; Plex login page is available; browser nonce persists without Cloudflare Access |
| Plex login protection | CSRF required to initiate login; repeated PIN starts rate-limited; callback rejects an incorrect nonce |
| Plex server membership | Plex users without access to the configured server are rejected in a mocked membership test |
| Authorization | Non-owner Plex user cannot approve or revoke sessions; anonymous approval denied; owner can revoke sessions |
| Proxy trust boundary | Spoofing Cloudflare identity headers does not grant access |
| Input validation | Bulk submission rejects malformed media IDs; unmapped Plex library submissions are refused |
| Collection routing | Movies, Kids Movies, Anime Movies, TV Shows, Kids TV Shows and Anime TV Shows route to their mapped Maintainerr collections; incompatible mappings are rejected |
| Request workflow | Shared users' bulk requests remain pending; owner single and bulk requests use auto-approval and the configured collection |
| Safe failure behavior | Ambiguous Maintainerr submissions enter `review`; duplicate retry does not trigger another upstream deletion request |
| Private history | Request history shows only the logged-in requester's titles; anonymous history access redirects to login |
| Deletion delay configuration | Minimum deletion-delay setting is configurable, with a one-day lower bound |

These are **offline unit/regression tests** using a temporary SQLite database and mocked upstream services. They are not a live Plex SSO penetration test, an authorization fuzzing campaign, or an end-to-end deletion confirmation.

### Reproduce the current verification on Unraid

```bash
docker build --pull --no-cache -f Dockerfile.alpine \
  -t local/media-approval-portal:v9-owner-history .

docker run --rm --entrypoint python \
  local/media-approval-portal:v9-owner-history /app/test_runtime.py

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  aquasec/trivy:latest image \
  --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
  local/media-approval-portal:v9-owner-history
```

The test command should end with `Ran 22 tests` and `OK` to count as a full pass. The Trivy command exits nonzero when it finds a HIGH or CRITICAL vulnerability (or encounters an error); inspect its output to distinguish findings from scan failures. Record the image tag/digest, scan date, Trivy version, and output if publishing reproducible evidence.

### Production safeguards and limitations

- **Plex-only SSO**: Plex verifies identity; the portal checks access to the specifically configured Plex server. Administrator privileges are based on the verified server-owner account, not a submitted email or proxy header.
- **Authorization enforcement**: Shared users can request deletions; approvals and session revocation are restricted to the owner.
- **Request integrity**: CSRF checks, login throttling, server-side library routing, input validation, duplicate-request checks and conservative `review` handling protect high-impact actions.
- **Maintainerr preflight**: Collection properties and media membership are checked before an approval is treated as successful. An `approved` status indicates confirmed handoff to Maintainerr, **not confirmed deletion** from storage, Plex, Radarr/Sonarr or Seerr.
- **Container hardening**: Recommended Unraid runtime flags include a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, a PID limit, a small temporary filesystem and a non-root application user.
- **Residual risks**: Verify Cloudflare edge rate limits, origin exposure, Plex account revocation behavior, all six Maintainerr collection assignments, server/library permissions and real downstream deletion outcomes. No independent security audit has been completed. The application is capable of initiating **irreversible deletion**.
- **Secrets**: Never commit `.env`, Plex tokens, encryption keys, SQLite databases, logs containing authentication tokens, or real scan data with secrets. Use `.env.example` only for placeholders.

---

## Release notes — v9

This version builds on v8 library-specific routing, preserving the same six Maintainerr collections and existing SQLite database.

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
