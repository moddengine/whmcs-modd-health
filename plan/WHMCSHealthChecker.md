# WHMCS Site Health Checker Specification

## Summary

This specification defines:

- A WHMCS addon that configures monitoring, creates the state table, and displays current failures.
- Bundled Linux `amd64` and `arm64` Go checker binaries.
- A PHP CLI wrapper, run every six minutes by system cron, which discovers eligible WHMCS services and passes a versioned JSON job to the binary through standard input.
- Site checks spread across five minutes, with a 60-second overall timeout per site.
- Google Chat notifications after two consecutive failures or two consecutive recoveries.

The checker replaces the prototype in `go/cmd/mehealth/mehealth.go`. It does not retain its cPanel discovery, etcd storage, hard-coded diagnostic domains, fallback URLs, or global `www`, nameserver, CDN, and video checks.

## Interfaces and Data Flow

### PHP cron wrapper

The PHP wrapper is the trust boundary and must:

1. Bootstrap WHMCS and read the addon settings.
2. Select `tblhosting` rows whose status is `Active`, whose domain is non-empty, and whose package ID belongs to exactly one configured health profile.
3. Select the bundled binary matching Linux `x86_64`/`amd64` or `aarch64`/`arm64`.
4. Prevent overlapping executions with a filesystem lock.
5. Send credentials and configuration to the binary as JSON through standard input.
6. Never expose credentials or the Google Chat webhook in command-line arguments, temporary files, output, or logs.

The wrapper is invoked by system cron every six minutes. If the preceding run still owns the lock, the new invocation exits successfully without starting another checker.

### JSON job

The input document must contain:

- Schema version.
- Unique run identifier.
- Scheduling window of 300 seconds.
- Per-site timeout of 60 seconds.
- MySQL host or socket, port, database, username, password, and TLS mode.
- Google Chat webhook URL.
- Shared configuration for each health profile.
- A list of sites, each containing its WHMCS service ID, client ID, package ID, domain, and assigned profile.

Unknown schema versions, missing required fields, invalid domains, duplicate services, invalid IP addresses, and invalid regular expressions must reject the entire job before any checks or database writes begin.

### Go checker

The checker must:

- Read exactly one JSON job from standard input.
- Validate the complete job before probing.
- Derive a deterministic start offset from the WHMCS service ID within the 0–300 second scheduling window.
- Run a site's independent DNS and HTTP checks concurrently under one 60-second context.
- Persist results and state transitions directly to MySQL.
- Emit one final non-secret JSON summary on standard output and diagnostic logs on standard error.
- Exit `0` when the monitoring run completes, even when sites are unhealthy.
- Exit nonzero only for invalid input or an operational failure that prevents the run from completing.

The final summary must contain the run ID, number of discovered and checked sites, pending failures, confirmed failures, state transitions, notification failures, and elapsed time.

## Health Profiles

All DNS names are queried without a trailing dot and compared after lowercasing and removing any trailing dot from returned hostnames.

### Email Hosting

For the service domain:

- At least one MX record must exist.
- Every returned MX target must match the configured MX regular expression.
- Exactly one SPF TXT record beginning with `v=spf1` must exist and match the configured SPF regular expression.
- For every configured DKIM selector, `<selector>._domainkey.<domain>` must have a CNAME whose target matches the configured DKIM CNAME regular expression.

Email Hosting does not perform an apex A-record or HTTP health check.

### Legacy Hosting

For the service domain:

- At least one IPv4 A record must exist.
- Every returned IPv4 address must be in the configured hosting IP list.
- `https://<domain>/~/health/check` must return HTTP `200` directly.

Redirects are not followed. Normal TLS certificate and hostname validation applies.

### Modd Container Hosting

The apex A-record and HTTP checks are identical to Legacy Hosting.

For both `edm.<domain>` and `notify.<domain>`:

- At least one MX record must exist.
- An SPF TXT record beginning with `v=spf1` must exist.

The MX targets and SPF contents for these two subdomains need not match the Email Hosting patterns.

### Network behaviour

- Use the operating system DNS resolver.
- The 60-second site timeout covers all DNS lookups, HTTP requests, and result collection for that site.
- A timeout, DNS error, TLS error, malformed response, or unexpected HTTP status fails only the affected check.
- A database failure is an operational error and must not be represented as a site-health failure.

## State and Notifications

### Database table

Addon activation creates `mod_mehealth_state`, with one row per WHMCS service. Use portable scalar and text columns rather than database-specific enum or JSON types.

The table stores:

- WHMCS service, client, and product identifiers.
- Domain and assigned profile.
- Stable state: `unknown`, `healthy`, or `failed`.
- Latest observed state: `healthy` or `failed`.
- Consecutive observation count.
- Latest individual check results encoded as JSON text.
- First failure observation time.
- Confirmed failure time.
- Last check and update times.
- Pending notification type.
- Last notification error and successful notification time.

Rows for services no longer present in a successful discovery job are removed after that run. A discovery or input failure must not prune existing rows.

Addon deactivation preserves the table and its data. Permanent removal is a separate, explicitly documented administrative action.

### State transitions

- A first-ever healthy observation establishes a silent healthy baseline.
- A first failure sets the observed state to failed, the consecutive count to one, and makes the site visible as `Pending confirmation` in WHMCS.
- A second consecutive failure changes the stable state to failed and queues one site-level failure notification.
- A healthy observation following one unconfirmed failure clears the pending failure without notification.
- A confirmed failed site requires two consecutive healthy observations before changing to healthy.
- The first healthy recovery observation remains visible as `Recovery pending`.
- The second consecutive healthy observation confirms recovery, removes the site from the failure list, and queues one recovery notification.
- Any observation opposite to the current sequence resets the consecutive count to one for the new observed state.
- Changing individual failure details while the stable state remains failed updates the WHMCS display but does not send another notification.

### Google Chat

Notifications use an incoming Google Chat webhook with a JSON body containing a plain `text` field.

- Send one message per site transition.
- Failure messages identify the domain, WHMCS service and product IDs, profile, and all failed checks.
- Recovery messages identify the domain and state that all required checks are healthy.
- Pace messages to no more than one request per second.
- Retry network failures, HTTP `429`, and HTTP `5xx` responses with bounded exponential backoff.
- Preserve an unsuccessful notification as pending and retry it on later runs.
- Do not repeat a successfully delivered transition notification.

## WHMCS Addon

### Configuration

The addon configuration provides:

- Email Hosting product IDs.
- Legacy Hosting product IDs.
- Modd Container Hosting product IDs.
- Shared permitted hosting IPv4 addresses.
- Email MX regular expression.
- Email SPF regular expression.
- DKIM selector list.
- DKIM CNAME regular expression.
- Google Chat webhook as a password field.

Products assigned to the same profile share that profile's expectations. A product ID must not appear in more than one profile.

Configuration errors must be shown in the WHMCS admin area and must prevent the cron wrapper from invoking the checker.

### Admin failure list

The addon admin page displays only pending and confirmed failures. It does not provide history, graphs, acknowledgement workflows, or manual probes.

Order rows by the first failure observation and show:

- Pending confirmation, confirmed failure, or recovery pending state.
- Domain linked to its HTTPS site.
- WHMCS service linked to the service administration page.
- Product ID and health profile.
- Failed checks and their current messages.
- Consecutive observation count.
- First observed and last checked times.

All rendered database and DNS values must be HTML-escaped.

## Distribution and Installation

The addon package contains statically built Linux binaries produced with `CGO_ENABLED=0` for:

- `GOOS=linux GOARCH=amd64`
- `GOOS=linux GOARCH=arm64`

Installation documentation must cover:

- WHMCS addon activation and access permissions.
- Addon configuration.
- Binary executable permissions.
- The six-minute system cron entry.
- Verification of PHP process execution support.
- Google Chat webhook registration.
- Safe database privileges and log handling.

## Acceptance Tests

### PHP wrapper

- Includes only selected Active services with non-empty domains.
- Rejects duplicate profile assignments and malformed configuration.
- Selects the correct architecture binary.
- Sends secrets through standard input and does not log them.
- Skips a run while another invocation owns the lock.
- Does not prune state when discovery fails.

### Health checks

- Exercise every profile with fake DNS results and an HTTP test server.
- Cover missing and unexpected A and MX records.
- Cover valid, missing, duplicate, and non-matching SPF records.
- Cover valid, missing, and non-matching DKIM CNAME records.
- Cover direct HTTP `200`, redirects, non-`200` responses, TLS errors, network errors, and timeouts.
- Verify deterministic offsets remain inside five minutes.
- Verify every site's complete check set shares one 60-second deadline.

### State machine

- `failed, failed` confirms failure and queues one alert.
- `failed, healthy` clears an unconfirmed failure without alerting.
- A confirmed failure requires `healthy, healthy` before recovery.
- Continued failures and changed failure details do not repeat alerts.
- Pending failures and pending recoveries remain visible with distinct labels.
- A healthy first observation creates no notification.

### Persistence and notifications

- Integration-test schema creation, state upserts, and stale-service pruning against MariaDB.
- Verify webhook success, retryable responses, permanent responses, pending delivery retention, pacing, and recovery messages.
- Verify site failures do not produce a failed process exit.
- Verify invalid input and database failures do produce a nonzero process exit.

### Builds

- Build and smoke-test the Linux `amd64` and `arm64` artifacts.
- Confirm the checker requires no ModdEngine packages, cPanel access, or etcd access.

## Deferred Features

The first version intentionally excludes:

- Historical reporting and graphs.
- Interactive Google Chat messages or threads.
- Manual checks and retry buttons.
- Per-product expectation overrides within a shared profile.
- IPv6 checks.
- HTTP fallback domains such as `new.<domain>` and `*.myudo.net`.
- Global nameserver, `www`, CDN, and video checks.

## Implementation Addendum

- The WHMCS addon/component name is `modd_health`.
- Delegated nameservers and their addresses are recorded. Required DNS records are queried directly from every delegated authoritative endpoint instead of through the caching resolver; one authoritative endpoint must satisfy the complete profile.
- Admin and client service details show **DNS Status** and **Health Status**. Health is `UP` or `Down since d j Y H:i:s (reason: ...)`.
- The administrator dashboard shows persisted UP/DOWN totals and links to the unhealthy-service list.
- Legacy and Container health URL templates are configurable per profile in the addon UI.
