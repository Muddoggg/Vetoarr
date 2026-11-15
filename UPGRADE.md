# Security hardening patch — upgrade guide

This is a source patch based on the available v9 code snapshot, **not** a checked or deployed GitHub commit. Existing Plex SSO, owner auto-approval, request history, and six collection IDs remain in place. Do not publish/merge the patch until it passes your own tests.

## Changes

1. `app.py` adds `CREATE UNIQUE INDEX ... ON requests(plex_id) WHERE status IN ('pending','processing','approved','review')`; duplicate active requests cause startup to fail with an explicit error rather than silently deleting history. Single requests now hold a SQLite `BEGIN IMMEDIATE` transaction before duplicate checks. Both bulk and single inserts handle `IntegrityError`.
2. `app.py` now compares the Maintainerr collection's `libraryId` against the actual Plex media `librarySectionID` **before** adding media to Maintainerr. A missing or mismatched ID fails closed and leaves the request pending. Collections 1–6 are still configured using your existing `.env`.
3. `.env.example` and `compose.yaml` use placeholders/loopback and no real IP, hostname or historical image version. These examples do not affect your existing Unraid Docker template unless you deploy via Compose.
4. `SECURITY.md` documents mandatory Cloudflare edge throttling and origin isolation. Rotating the browser cookie still bypasses the browser-bound local throttle, so **you must add the WAF rule**. App-side rate limiting cannot reliably use spoofable forwarded IP headers.
5. New tests exercise SQLite index uniqueness, concurrent inserts, rejected-request re-submission, and Maintainerr library mismatch. No real media is modified by the test suite.

## Deployment gates (before switching running image)

### 1. Inspect existing DB before migrating

On Unraid, run this **read-only** check (host database path below reflects your existing installation):

```bash
python3 - <<'PY'
import sqlite3
p='/mnt/user/appdata/media-approval-portal/requests.sqlite3'
c=sqlite3.connect(f'file:{p}?mode=ro', uri=True)
for plex_id,count in c.execute("""SELECT plex_id, COUNT(*) FROM requests
 WHERE status IN ('pending','processing','approved','review')
 GROUP BY plex_id HAVING COUNT(*) > 1"""):
    print('DUPLICATE:',plex_id,count)
c.close()
PY
```

No output means the new unique index should not be blocked by duplicate request rows. If rows appear, stop and resolve manually **without deleting history**.

### 2. Verify each Maintainerr collection's libraryId before making approvals

From your existing running portal:

```bash
docker exec -i media-approval-portal python - <<'PY'
import os,requests
base=os.environ['MAINTAINERR_URL'].rstrip('/')
for label,key in [('Movies','MOVIE_COLLECTION_ID'),('TV Shows','SHOW_COLLECTION_ID'),('Kids Movies','KIDS_MOVIE_COLLECTION_ID'),('Anime Movies','ANIME_MOVIE_COLLECTION_ID'),('Kids TV','KIDS_SHOW_COLLECTION_ID'),('Anime TV','ANIME_SHOW_COLLECTION_ID')]:
    r=requests.get(f'{base}/api/collections/collection/{os.environ[key]}',timeout=10)
    r.raise_for_status()
    data=r.json()
    print(f'{label}: collection={data.get("id")}, libraryId={data.get("libraryId")}, type={data.get("type")}, delay={data.get("deleteAfterDays")}')
PY
```

Each `libraryId` must match the corresponding **Plex library section ID**, *not* its Maintainerr collection ID. Correct mismatches in the Maintainerr UI before retrying. Do not automate collection modifications through an unverified API payload.

### 3. Build and run tests on Unraid

In the patched source directory:

```bash
docker build --pull --no-cache -f Dockerfile.alpine -t local/media-approval-portal:security-hardening .
docker run --rm --entrypoint python local/media-approval-portal:security-hardening /app/test_runtime.py
```

All tests must report `OK`. Run a fresh Trivy HIGH/CRITICAL scan against `local/media-approval-portal:security-hardening` with your existing command before deployment.

### 4. Cloudflare WAF and origin checks

In your Cloudflare zone WAF dashboard, create a **rate limiting rule** on `POST /auth/plex/start` for your portal host, grouped by source IP. Example expression (replace hostname):

```
(http.host eq "cleanup.example.com" and http.request.uri.path eq "/auth/plex/start" and http.request.method eq "POST")
```

Use a reasonable threshold for real users (for example 10 requests/60 seconds/IP, with a temporary block), adjusted for your plan and NAT/shared IP needs. Add protections for abusive callback/login traffic as available. **Do not delete Cloudflare Access on the assumption that Plex SSO is sufficient without this boundary.**

Verify from an external connection that direct access to your WAN IP cannot reach the portal or NPM admin. Keep Cloudflare proxy and TLS enabled, or adopt Cloudflare Tunnel; do not add a WAN port forward to 8085.

### 5. Back up and switch

Stop the container, back up the SQLite database while stopped, and update **only** the Docker image to the tested tag. Keep your *existing* `.env`, port 8085, `media` network and persistent database mapping. The `compose.yaml` is a generic example, not a replacement for your Unraid Docker template. On startup, the migration creates the unique index automatically. Check startup logs and `/login` (behind normal auth). Test approved/unshared/shared roles with non-destructive requests, and check Maintainerr membership before allowing new deletes.

## GitHub publishing

The package includes a baseline README, but your GitHub README may be more current. **Do not overwrite your customized GitHub README blindly.** Merge the security note or link `SECURITY.md`; commit changed source, tests, `.env.example`, Compose, `SECURITY.md`, and this guide. No `.env` or SQLite database should be included.

## Verification status

The Python files were syntax-checked locally and the archive was checked. Full Flask runtime tests and Trivy must run in your Docker environment. This patch is not a substitute for an end-to-end SSO and destructive-operation test.
