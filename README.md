# Modd Health

`modd_health` is a WHMCS addon that monitors selected hosting products using direct authoritative DNS queries and HTTPS health checks. It records current state in WHMCS, alerts through Google Chat after two matching observations, adds DNS and health information to service pages, and supplies an administrator dashboard widget.

## Development

Enter the reproducible development shell and run all checks:

```shell
nix-shell --run 'composer install && composer qa && go test -mod=mod ./... && actionlint && shellcheck bin/build-release'
```

Create an installable release locally:

```shell
nix-shell --run 'composer install && bin/build-release 1.0.0'
```

The resulting `whmcs-modd-health-1.0.0.zip` includes the addon, both static Linux checker binaries, and the manifest consumed by [WHMCS Plugin Updater](https://github.com/moddengine/whmcs-plugin-updater).

## Installation

1. Extract the release at the WHMCS root so `modules/addons/modd_health` is created.
2. Confirm both files under `modules/addons/modd_health/bin` are executable by the WHMCS cron user.
3. Activate **Modd Health** under **System Settings → Addon Modules** and grant access only to appropriate administrator roles.
4. Open **Addons → Modd Health**, assign products to profiles, and configure DNS patterns, permitted IPs, health URLs, database TLS, and the Google Chat webhook.
5. Allow the cron host outbound TCP and UDP port 53 to public authoritative nameservers and HTTPS to monitored sites and Google Chat.
6. Add this system cron entry, adjusting the paths and PHP binary:

   ```cron
   */6 * * * * /usr/bin/php /path/to/whmcs/modules/addons/modd_health/cron.php >>/var/log/modd-health.log 2>&1
   ```

The PHP CLI must permit `proc_open`, `flock`, and execution of the bundled checker. The database user needs normal WHMCS table access; credentials and the webhook are transferred only through the checker's standard input and must not be written to logs.

## Mail DNS checks

All profiles check service-domain mail policies. Email hosting still requires usable MX records, its configured MX/SPF patterns, and DKIM CNAMEs. Legacy and container hosting require SPF and DMARC only when the service domain has a usable MX target; absent MX and a sole null MX (`0 .`) skip these policies. DNS errors and malformed null MX combinations fail health checks.

SPF must be a single syntactically valid TXT policy. Container hosting also validates exactly one SPF policy on each of `edm` and `notify`, alongside their required MX records. DMARC accepts monitoring policies (`p=none`), including RFC 9989's default when `p` is omitted. Inherited policies use RFC 9989's bounded DNS tree walk and `psd` boundaries without a public-suffix-list dependency. Malformed or duplicate policies encountered during discovery fail the check.

The service's own records are queried directly from each authoritative endpoint. Inherited DMARC policies use the system resolver because parents may have different authorities. The complete profile is also checked through the system recursive resolver alongside direct queries, within the existing site timeout. If no authoritative endpoint passes but recursive resolution satisfies the complete profile, the site passes using those recursive results without direct-query warnings. NS differences or missing NS answers alone do not fail a site that passes recursive validation. Recursive answers may be cached until their TTL expires. The DNS summary shows SPF/DMARC validity, skipped checks, and the selected DMARC policy domain; older results keep their previous display.

Health reasons summarize each failing record once across authoritative servers. Lookup failures are distinguished from missing records; detailed server errors remain in the saved authority observations.

These checks validate syntax and publication. They do not resolve SPF includes/redirects, evaluate lookup budgets, or test mail delivery. Permissive policies are accepted. Deploying the updated checker may reveal failures under the existing two-observation confirmation rules. No configuration or database migration is needed.

## Removal

Deactivation deliberately retains `mod_modd_health_config` and `mod_modd_health_state`. After taking a database backup and deactivating the addon, permanently remove its data with:

```sql
DROP TABLE mod_modd_health_state, mod_modd_health_config;
```
