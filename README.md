# docker-image-check

`./docker-audit.sh [-a]` audits every running container (`-a` also includes stopped ones) and the host:

- **Freshness**: checks whether the same tag has a newer build in the registry, whether newer patch/minor or major tags exist (same variant, e.g. `-alpine`), and whether a container still runs an older image than the local tag points to.
- **CVEs**: runs Trivy (`aquasec/trivy:0.76.2` in a container, DB cached in the `trivy-cache` volume) on every image and on the host's OS packages.
- **Actively exploited**: checks every finding against the CISA KEV catalog (downloaded fresh each run). This is the generic catch for NGINX2Shell, PHP2Shell and whatever comes next.
- **Watchlist** (`watchlist.tsv`): runs version probes inside each container (`nginx -v`, `php -v`, ...) to catch software built from source, which Trivy cannot see. To cover a new "X2Shell", add a row; no code change needed.
- **Kernel**: compares the running kernel with the newest installed one and flags a pending reboot.

Output goes to `logs/<timestamp>/`:
- `audit.log`: the report
- `trivy/*.json`: raw scans
- `update.sh`: generated, never run automatically. Review it, then run it. Each block asks for confirmation.
  - Compose stacks: patch/minor tags are rewritten in the compose files (a `.bak-<epoch>` copy is kept), then `pull` and `up -d --no-deps` run for only the running services from those files. First it checks that compose still resolves every service to the image it runs now; this catches tags from shell variables like `${VERSION}` that are no longer set. Stopped containers stay stopped. Major bumps appear only as commented-out lines.
  - Standalone `docker run` containers: the run command is rebuilt from `docker inspect`. Env values are not copied, so export them first. If the new container fails to start, the old one is restored.

Exit codes: `2` = KEV or watchlist hit, `1` = CRITICAL found and CRITICAL/HIGH fixes available, `0` = nothing urgent. This makes it usable from cron:
`0 7 * * * /path/docker-audit.sh >/dev/null 2>&1 || notify-send "docker audit: action needed"`

Self-test of the version/tag logic: `./docker-audit.sh --selftest`

Needs: docker (with buildx), jq, curl. Private registries use `~/.docker/config.json` (`auths` entries only; credential helpers do not work inside the crane container).
