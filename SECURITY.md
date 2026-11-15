# Security policy and deployment boundary

This project initiates destructive media operations. Deploy only after configuring your own secrets and confirming API permissions.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting if enabled. Do not publish tokens, payloads, or live private hostnames in a public issue. Maintainers should rotate exposed credentials and coordinate fixes before disclosure.

## Required edge and origin controls

* Keep TLS and Cloudflare proxy/WAF enabled for public use.
* In Cloudflare Security → WAF → Rate limiting rules, match `http.host eq "portal.example.com" and http.request.uri.path eq "/auth/plex/start" and http.request.method eq "POST"`; count by source IP, choose an appropriate low threshold (e.g. 10 requests per minute) and block/challenge excess. The edge rule is **required**: browser cookie rotation defeats the built-in nonce throttle. Also consider limiting `/auth/plex/callback` and abusive requests to `/login`.
* An edge threshold must be tuned for shared IP addresses; do not treat an IP as a verified identity.
* Restrict the origin: no public router port forwarding to the portal or NPM administrative interface. Ideally use Cloudflare Tunnel or firewall allowlists for Cloudflare ingress, with authenticated origin-to-edge transport.
* Do not rely on request-provided `CF-Connecting-IP` or `X-Forwarded-For` unless a trusted reverse-proxy trust chain has been explicitly configured.
* Keep the portal database and `.env` outside Git, with restricted filesystem permissions.

## Maintainerr configuration

Each configured collection must have a `libraryId` matching the actual Plex `librarySectionID` for that media, matching type, active status, action 0 (delete), and deletion delay at least `MIN_DELETE_DAYS` (defaults to 7 unless explicitly set). The portal fails closed when the library assignment is missing or different. Ensure manual collection membership is intended and rule-based auto-selection is disabled where appropriate.

## Validation expectations

Run `python test_runtime.py` in the built image and a fresh Trivy scan on the exact image, then test with owner, shared, and unshared Plex accounts before public use. Neither static checks nor Trivy alone prove live security. Do not run approval tests against media you want to keep.
