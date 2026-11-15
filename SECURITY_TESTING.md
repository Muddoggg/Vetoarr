# Security verification record

**Project:** Vetoarr
**Evidence date:** November 15, 2026
**Image tested:** `local/media-approval-portal:security-hardening`
**Evidence source:** operator-shared Unraid command output, Git/Gitleaks output, and Cloudflare/OPNsense screenshots. Results are point-in-time; this document is not an independent audit or certification.

## Summary

| Check | Result | Notes |
| --- | --- | --- |
| Python automated tests | **30/30 PASS** | 0.445 seconds; `OK` |
| Trivy HIGH vulnerabilities | **0 found** | Alpine 3.24.4 and discovered Python packages |
| Trivy CRITICAL vulnerabilities | **0 found** | Same exact image and scan |
| Git-history secret scan | **0 findings** | Gitleaks scanned 4 commits / ~75.40 KB |
| Working-directory secret scan | **0 findings** | Gitleaks scanned ~74.63 KB |
| Duplicate active requests in live SQLite database | **None found** | Read-only pre-migration query |
| Edge login protection | **Active** | Cloudflare dashboard showed scoped rule; traffic not stress-tested |
| Origin IPv4 test | **Filtered from one external scanner** | TCP/443 on public IP; not an exhaustive bypass test |

### Automated regression coverage — 26 passing cases

The image's test runner reported these checks as passing:

| # | Test name | Security / behavior checked |
| ---: | --- | --- |
| 1 | `test_anonymous_history_requires_login` | History requires authentication |
| 2 | `test_anonymous_user_must_authenticate` | Anonymous users cannot access protected screens |
| 3 | `test_browser_nonce_stored_without_cloudflare_access` | Browser nonce works without Access JWT |
| 4 | `test_bulk_rejects_unvalidated_ids` | Malformed bulk media input rejected |
| 5 | `test_bulk_requests_stay_pending` | Shared users' bulk requests require approval |
| 6 | `test_collection_library_id_must_match` | Maintainerr `libraryId` must match Plex section |
| 7 | `test_concurrent_db_inserts_only_one_wins` | Concurrent same-media inserts do not both succeed |
| 8 | `test_db_rejects_duplicate_active_requests` | SQLite index rejects duplicate active requests |
| 9 | `test_one_day_policy_is_configurable` | Configured one-day minimum is supported |
| 10 | `test_owner_ambiguous_submission_never_auto_retries` | Uncertain deletion handoffs enter manual review |
| 11 | `test_owner_bulk_auto_approve` | Owner bulk requests follow approved workflow |
| 12 | `test_owner_can_view_and_revoke` | Owner has protected administrative functions |
| 13 | `test_owner_single_request_auto_approved` | Owner single request uses auto-approval safeguards |
| 14 | `test_pin_start_rate_limit` | Browser-scoped PIN initiation throttling |
| 15 | `test_pin_start_requires_csrf` | CSRF required to start Plex PIN flow |
| 16 | `test_plex_callback_requires_nonce` | Callback nonce validated |
| 17 | `test_plex_login_page` | Sign-in page is available |
| 18 | `test_rejected_media_can_be_requested_again` | Rejected requests don't permanently block re-request |
| 19 | `test_requester_cannot_approve` | Shared user cannot approve deletions |
| 20 | `test_requester_cannot_revoke` | Shared user cannot revoke sessions |
| 21 | `test_requester_history_is_private` | History is requester-scoped |
| 22 | `test_six_library_routes` | All six Plex/collection mappings are covered |
| 23 | `test_spoofed_cloudflare_headers_do_not_grant_access` | Untrusted identity headers do not authenticate users |
| 24 | `test_unauthed_approval_denied` | Anonymous admin approval denied |
| 25 | `test_unauthorized_server_membership_denied` | Accounts without server membership denied |
| 26 | `test_unmapped_library_refused_during_request` | Unknown library routes fail closed |

One test intentionally emitted `WARNING:app:Approval 4 needs review: Timeout` while simulating an ambiguous Maintainerr failure. The test itself passed; the warning is expected and confirms fail-safe handling.

**Scope:** These are mostly unit/regression tests with mocked Plex/Maintainerr APIs and a test SQLite database. They do not prove that every actual Plex authorization flow, session revocation, proxy path, or media deletion behaves correctly in production.

## Trivy scan (November 15, 2026)

**Command:**

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  aquasec/trivy:latest image \
  --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
  local/media-approval-portal:security-hardening
```

Observed Trivy output included:

- Vulnerability database freshly downloaded.
- OS: `alpine 3.24.4`, 38 OS packages detected.
- Python dependency metadata detected and scanned.
- Every listed Alpine and Python-package target: `0` matching findings.
- **No HIGH or CRITICAL findings identified** in the specified image at scan time.

This scan was restricted to HIGH/CRITICAL severities; it **does not establish zero LOW/MEDIUM vulnerabilities**. It also does not detect all business-logic vulnerabilities or weaknesses introduced outside the image.

## Secrets scans (November 15, 2026)

```bash
gitleaks git . --redact
gitleaks dir . --redact
```

Observed: `4 commits scanned`, about `75.40 KB` history and `74.63 KB` directory scanned, with `no leaks found` in each. This is a detection result, **not a guarantee** that arbitrary tokens, private hostnames, personal data, or credentials are absent. Check the tracked and historical files manually before publishing.

## Edge and origin validation (November 15, 2026)

- Cloudflare's `Media Portal - Plex Login Protection` rate-limiting rule appeared **Active**, with Block action, scoped to the cleanup hostname and `POST /auth/plex/start`. The specific enforcement threshold/duration should be documented from the saved rule configuration rather than inferred from screenshots.
- OPNsense `Cloudflare_IPv4` URL-table alias populated with 15 IPv4 CIDR networks; WAN TCP/443 Destination NAT and the corresponding pass rule were configured for the alias according to operator observations.
- An outside port-check service reported public IPv4 port **443: filtered**. That supports IPv4 direct-origin filtering from that scanner's location only.
- A direct test made from inside the home reached OPNsense's DNS-rebinding warning page; because it originated on the local network, **it is not evidence of a WAN bypass**.
- Still to verify: origin IPv6 path, other externally exposed ports, whether the service remains reachable through Cloudflare, and any proxy/CDN authentication bypass paths.

## Reproduce from the hardened source

```bash
docker build --pull --no-cache -f Dockerfile.alpine \
  -t local/media-approval-portal:security-hardening .

docker run --rm --entrypoint python \
  local/media-approval-portal:security-hardening /app/test_runtime.py

docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  aquasec/trivy:latest image \
  --scanners vuln --severity HIGH,CRITICAL --exit-code 1 \
  local/media-approval-portal:security-hardening
```

A repeat build with `--pull` may resolve to newer packages. Re-run both tests and scanning and record the **image digest**, date, scanner version, and full output if you intend to publish reproducible evidence.

## Public-release gate

Before making a repository public, verify that the repository contains the **hardened** application and regression tests (not an older release), compare `.env.example` and `compose.yaml` with your actual deployment only in private, confirm `.env` and all SQLite files are ignored, scan *Git history* as well as the working tree, and review all code/configuration for embedded tokens and identifying values. Keep production configuration and incident logs out of public commits. Live shared/unshared Plex access testing and end-to-end deletion checks remain important regardless of image scan results.
