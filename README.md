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
