#!/usr/bin/env bash
# Audit running Docker containers and the host: outdated images, open CVEs (Trivy),
# actively exploited CVEs (CISA KEV), watchlist probes (watchlist.tsv).
# Output: logs/<timestamp>/{audit.log,update.sh,trivy/*.json,kev.json}. update.sh is generated, never run.
# Usage: ./docker-audit.sh [-a]   (-a: include stopped containers)   |   ./docker-audit.sh --selftest
# Exit: 2 = KEV or watchlist hit, 1 = CRITICAL found and CRITICAL/HIGH fixes available, 0 = nothing urgent.
set -uo pipefail

# pinned by digest: trivy gets the docker socket (root), crane gets registry tokens
TRIVY_IMG=aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
CRANE_IMG=gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1
KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
HERE=$(cd "$(dirname "$0")" && pwd)
WATCHLIST=${WATCHLIST:-$HERE/watchlist.tsv}

# ---------- pure helpers (covered by --selftest) ----------
ver() { grep -oE '[0-9]+(\.[0-9]+)+' <<<"$1" | head -1; }
ver_lt() { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1) == "$1" ]]; }

# is_vuln VERSION "f1,f2,..": below the fix of its own major.minor branch, or (no fix for its branch) below the newest fix
is_vuln() {
  local v=$1 br=${1%.*} max= f fs
  IFS=, read -ra fs <<<"$2"
  for f in "${fs[@]}"; do
    if [[ ${f%.*} == "$br" ]]; then ver_lt "$v" "$f"; return; fi
    if [[ -z $max ]] || ver_lt "$max" "$f"; then max=$f; fi
  done
  ver_lt "$v" "$max"
}

# pick_newer TAG < tag list: prints "<tag> minor" (newest, same major) and/or "<tag> major" (newest overall).
# Only tags with the same prefix (v or none), suffix (-alpine, -glibc, "") and number of version parts count.
# For 0.x the first two numbers are the major (0.21 -> 0.30 may break, like a major bump).
TAGRE='^(v?)([0-9]+(\.[0-9]+)*)(.*)$'
MAJKEY='{ k = ($1 == "0" && NF > 1) ? $1 "." $2 : $1 }'
pick_newer() {
  local tag=$1 pre num suf dots t cands mk same all
  [[ $tag =~ $TAGRE ]] || return 0
  pre=${BASH_REMATCH[1]} num=${BASH_REMATCH[2]} suf=${BASH_REMATCH[4]} dots=${num//[^.]/}
  cands=$(while read -r t; do
      [[ $t =~ $TAGRE ]] || continue
      [[ ${BASH_REMATCH[1]} == "$pre" && ${BASH_REMATCH[4]} == "$suf" && ${BASH_REMATCH[2]//[^.]/} == "$dots" ]] && echo "${BASH_REMATCH[2]}"
    done; echo "$num")
  cands=$(sort -uV <<<"$cands")
  mk=$(awk -F. "$MAJKEY"' { print k }' <<<"$num")
  same=$(awk -F. -v m="$mk" "$MAJKEY"' k == m' <<<"$cands" | tail -1)
  all=$(tail -1 <<<"$cands")
  [[ $same != "$num" ]] && echo "$pre$same$suf minor"
  [[ $(awk -F. "$MAJKEY"' { print k }' <<<"$all") != "$mk" ]] && echo "$pre$all$suf major"
  return 0
}

selftest() {
  local fail=0
  t() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
  local NG=1.30.7,1.31.9 PHP=8.2.35,8.3.36,8.4.27,8.5.12
  t "nginx 1.30.6 vulnerable"           "is_vuln 1.30.6 $NG"
  t "nginx 1.30.7 fixed"                "! is_vuln 1.30.7 $NG"
  t "nginx 1.31.8 vulnerable"           "is_vuln 1.31.8 $NG"
  t "nginx 1.31.10 fixed"               "! is_vuln 1.31.10 $NG"
  t "nginx 1.29.0 vulnerable (no fix)"  "is_vuln 1.29.0 $NG"
  t "nginx 1.32.0 fixed"                "! is_vuln 1.32.0 $NG"
  t "php 8.3.35 vulnerable"             "is_vuln 8.3.35 $PHP"
  t "php 8.4.27 fixed"                  "! is_vuln 8.4.27 $PHP"
  t "php 8.1.31 vulnerable (EOL)"       "is_vuln 8.1.31 $PHP"
  t "version parse nginx"  '[[ $(ver "nginx version: nginx/1.29.0") == 1.29.0 ]]'
  t "version parse php"    '[[ $(ver "PHP 8.3.10 (cli) (built: x) Zend Engine v4.3.10") == 8.3.10 ]]'
  t "variant: 17-alpine -> 18-alpine major" \
    '[[ $(printf "%s\n" 17-alpine 18-alpine 17.2-alpine latest 19-bookworm | pick_newer 17-alpine) == "18-alpine major" ]]'
  t "semver: minor and major" \
    '[[ $(printf "%s\n" 1.0.0 1.0.1 1.1.0-rc1 1.2.0 2.0.0 | pick_newer 1.0.0) == $'"'"'1.2.0 minor\n2.0.0 major'"'"' ]]'
  t "suffix kept"   '[[ $(printf "%s\n" 1.0.0-glibc 1.0.2-glibc 1.0.3 | pick_newer 1.0.0-glibc) == "1.0.2-glibc minor" ]]'
  t "nothing newer" '[[ -z $(printf "%s\n" 1.0.0 0.9.0 | pick_newer 1.0.0) ]]'
  t "latest: no tag logic" '[[ -z $(printf "%s\n" 1.0 latest | pick_newer latest) ]]'
  t "v prefix kept"  '[[ $(printf "%s\n" v3.1 v3.4 3.9 v4.0 | pick_newer v3.1) == $'"'"'v3.4 minor\nv4.0 major'"'"' ]]'
  t "0.x minor is major" '[[ $(printf "%s\n" 0.21.0 0.21.3 0.30.0 | pick_newer 0.21.0) == $'"'"'0.21.3 minor\n0.30.0 major'"'"' ]]'
  # update.sh helpers, loaded from the generated header
  source <(update_header)
  local tf; tf=$(mktemp)
  printf '%s\n' '    image: rustfs/rustfs:1.0.0' '    image: "rustfs/rustfs:1.0.0" # q' '    image: rustfs/rustfs:1.0.0-glibc' '  # image: rustfs/rustfs:1.0.0' > "$tf"
  bump rustfs/rustfs:1.0.0 rustfs/rustfs:1.0.6 "$tf" >/dev/null
  t "bump: plain + quoted, keeps variant and comments" \
    '[[ $(<"$tf") == $'"'"'    image: rustfs/rustfs:1.0.6\n    image: "rustfs/rustfs:1.0.6" # q\n    image: rustfs/rustfs:1.0.0-glibc\n  # image: rustfs/rustfs:1.0.0'"'"' ]]'
  t "bump: backup written" '[[ $(cat "$tf".bak-* | head -1) == "    image: rustfs/rustfs:1.0.0" ]]'
  rm -f "$tf" "$tf".bak-*
  fakedc() { echo '{"services":{"web":{"image":"app:latest"},"db":{"build":{}}}}'; }
  t "check_images: tag variable unset -> stop" '! check_images "web=app:1.11" fakedc >/dev/null'
  t "check_images: match, build-only skipped" 'check_images "web=app:latest db=proj-db" fakedc >/dev/null'
  exit $fail
}

# ---------- runtime helpers ----------
log() { echo "[$(date +%T)] $*" >&2; }
need() { for c; do command -v "$c" >/dev/null || { echo "missing: $c" >&2; exit 3; }; done; }
q() { printf '%q' "$1"; }
crane() { docker run --rm --user "$(id -u)" -e DOCKER_CONFIG=/cfg -v "$HOME/.docker/config.json:/cfg/config.json:ro" "$CRANE_IMG" "$@" 2>/dev/null; }
trivy() { docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache "$@"; }

# run_in TARGET CMD..: TARGET is a container name or "host"; no shell needed inside the container
run_in() {
  local t=$1; shift
  if [[ $t == host ]]; then command -v "$1" >/dev/null && timeout 20 "$@" 2>&1 </dev/null
  else timeout 20 docker exec "$t" "$@" 2>&1 </dev/null; fi
}

# split_ref REF -> REPO TAG (TAG empty if pinned by digest)
split_ref() {
  local r=$1 last=${1##*/}
  if [[ $r == *@* ]]; then REPO=${r%@*}; TAG=; return; fi
  if [[ $last == *:* ]]; then REPO=${r%:*}; TAG=${r##*:}; else REPO=$r; TAG=latest; fi
}

# summary of a trivy JSON: CRIT|HIGH|FIXABLE(crit+high)|KEV-ids (unique CVE ids)
trivy_sum() {
  jq -r --slurpfile k "$OUT/kev-ids.json" '
    ($k[0]) as $kev | [.Results[]?.Vulnerabilities[]?] as $v |
    def ids(f): $v | map(select(f)) | map(.VulnerabilityID) | unique;
    [ (ids(.Severity=="CRITICAL")|length), (ids(.Severity=="HIGH")|length),
      (ids((.Severity=="CRITICAL" or .Severity=="HIGH") and (.FixedVersion//"")!="")|length),
      (ids($kev[.VulnerabilityID])|join(",")) ] | map(tostring) | join("|")' "$1" 2>/dev/null || echo "?|?|?|"
}

# detail lines: KEV first, then CRITICAL, then fixable HIGH
trivy_detail() {
  jq -r --slurpfile k "$OUT/kev-ids.json" '
    ($k[0]) as $kev |
    [.Results[]? | .Target as $t | .Vulnerabilities[]? | . + {kev: ($kev[.VulnerabilityID] // false), t: $t}
      | select(.kev or .Severity=="CRITICAL" or (.Severity=="HIGH" and (.FixedVersion//"")!=""))]
    | unique_by(.VulnerabilityID + .PkgName)
    | sort_by((if .kev then 0 elif .Severity=="CRITICAL" then 1 else 2 end), .VulnerabilityID)[]
    | "      \(if .kev then "KEV!" else .Severity[0:4] end) \(.VulnerabilityID) \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion // "no fix") \((.Title // "")[0:70])"' "$1" 2>/dev/null
}

# watchlist probes for TARGET; prints report lines, records hits in WATCH[TARGET]
probe() {
  local tgt=$1 name cmd fixed cves ecmd ere note out v st argv
  while IFS=$'\t' read -r name cmd fixed cves ecmd ere note; do
    [[ -z $name || $name == \#* ]] && continue
    read -ra argv <<<"$cmd"
    out=$(run_in "$tgt" "${argv[@]}"); v=$(ver "$out")
    [[ -z $v ]] && continue
    if [[ $fixed == - ]]; then echo "    $name $v"; continue; fi
    if is_vuln "$v" "$fixed"; then
      st="VULNERABLE: $cves ($note)"
      if [[ $ecmd != - ]]; then
        read -ra argv <<<"$ecmd"; out=$(run_in "$tgt" "${argv[@]}")
        if grep -Eq "$ere" <<<"$out"; then st+=" - exposure condition MET"; else st+=" - exposure condition not detected, verify manually"; fi
      fi
      WATCH[$tgt]+="$name $v; "
    else st="ok (fixes: $fixed)"; fi
    echo "    $name $v: $st"
  done < "$WATCHLIST"
}

main() {
  local ALL=
  case ${1:-} in
    --selftest) selftest ;;
    -a) ALL=-a ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
  esac
  need docker jq curl timeout awk
  OUT=$HERE/logs/$(date +%Y%m%d-%H%M%S); mkdir -p "$OUT/trivy"
  local LOG=$OUT/audit.log UPD=$OUT/update.sh

  log "pulling $TRIVY_IMG / $CRANE_IMG"
  docker pull -q "$TRIVY_IMG" >/dev/null && docker pull -q "$CRANE_IMG" >/dev/null || { echo "cannot pull tool images" >&2; exit 3; }

  log "downloading CISA KEV catalog"
  local KEVINFO="CISA KEV: UNAVAILABLE (KEV cross-check skipped)"
  if curl -fsSL --max-time 60 "$KEV_URL" -o "$OUT/kev.json"; then
    KEVINFO=$(jq -r '"CISA KEV: catalog \(.catalogVersion), released \(.dateReleased), \(.count) CVEs"' "$OUT/kev.json")
    jq '[.vulnerabilities[].cveID | {(.): true}] | add' "$OUT/kev.json" > "$OUT/kev-ids.json"
  else echo '{}' > "$OUT/kev-ids.json"; fi

  # ---------- inventory ----------
  local ids; ids=$(docker ps $ALL -q)
  if [[ -n $ids ]]; then docker inspect $ids > "$OUT/containers.json"; else echo '[]' > "$OUT/containers.json"; fi
  # fields: name|ref|imageid|state|project|config_files|working_dir|service ("-" = none)
  mapfile -t INV < <(jq -r '.[] | [(.Name|ltrimstr("/")), .Config.Image, .Image, .State.Status,
      (.Config.Labels["com.docker.compose.project"] // "-"), (.Config.Labels["com.docker.compose.project.config_files"] // "-"),
      (.Config.Labels["com.docker.compose.project.working_dir"] // "-"), (.Config.Labels["com.docker.compose.service"] // "-")]
      | join("|")' "$OUT/containers.json" | sort)

  declare -gA SUM=() TFILE=() STALE=() MINOR=() MAJOR=() RNOTE=() RESTART=() PROBES=() WATCH=()
  local line name ref id state proj files wd svc

  # ---------- CVE scan per unique image ----------
  for line in "${INV[@]}"; do
    IFS='|' read -r name ref id state proj files wd svc <<<"$line"
    [[ -n ${SUM[$id]:-} ]] && continue
    local f="$OUT/trivy/$(tr '/:@' '___' <<<"$ref")-${id:7:12}.json"
    log "trivy: $ref (${id:7:12})"
    if trivy "$TRIVY_IMG" image --quiet --format json --scanners vuln "$id" > "$f" 2>"$f.err"; then
      SUM[$id]=$(trivy_sum "$f"); rm -f "$f.err"
    else SUM[$id]="?|?|?|"; fi
    TFILE[$id]=$f
  done

  # ---------- freshness per unique ref ----------
  for line in "${INV[@]}"; do
    IFS='|' read -r name ref id state proj files wd svc <<<"$line"
    [[ -n ${STALE[$ref]:-} ]] && continue
    split_ref "$ref"
    if [[ -z $TAG ]]; then STALE[$ref]=pinned; RNOTE[$ref]="pinned by digest"; continue; fi
    log "registry: $ref"
    local remote local_digests nt
    remote=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest}}' 2>"$OUT/registry.err" | jq -r '.digest // empty')
    local_digests=$(docker image inspect -f '{{join .RepoDigests " "}}' "$id" 2>/dev/null)
    if [[ -z $remote ]] && grep -qE '401|403|denied|unauthorized' "$OUT/registry.err"; then
      STALE[$ref]="?"; RNOTE[$ref]="registry DENIED access - stored login rejected, run: docker login ${REPO%%/*}"
    elif [[ -z $remote ]]; then STALE[$ref]="?"; RNOTE[$ref]="not in registry (local build?)"
    elif [[ $local_digests == *"$remote"* ]]; then STALE[$ref]=no
    else STALE[$ref]=yes; RNOTE[$ref]="new build of tag :$TAG in registry"; fi
    [[ -n $remote ]] || continue
    nt=$(crane ls "$REPO" | pick_newer "$TAG")
    MINOR[$ref]=$(awk '$2=="minor"{print $1}' <<<"$nt")
    MAJOR[$ref]=$(awk '$2=="major"{print $1}' <<<"$nt")
  done

  rm -f "$OUT/registry.err"

  # ---------- per container: restart check + probes ----------
  for line in "${INV[@]}"; do
    IFS='|' read -r name ref id state proj files wd svc <<<"$line"
    local tagid; tagid=$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null)
    [[ -n $tagid && $tagid != "$id" ]] && RESTART[$name]=yes
    [[ $state == running ]] || { PROBES[$name]="    (not running, probes skipped)"; continue; }
    log "probes: $name"
    probe "$name" > "$OUT/probe.txt"; PROBES[$name]=$(<"$OUT/probe.txt")  # no $(): WATCH must survive
  done

  # ---------- host ----------
  log "trivy: host rootfs (OS packages)"
  local HF=$OUT/trivy/host-rootfs.json HSUM
  # shortcut: OS packages only (home dirs full of node_modules would drown the report); scan project dirs separately if needed
  if docker run --rm -v /:/host:ro -v trivy-cache:/root/.cache "$TRIVY_IMG" rootfs --quiet --format json --scanners vuln \
       --pkg-types os --skip-dirs /host/proc,/host/sys,/host/dev,/host/run,/host/home,/host/tmp,/host/media,/host/mnt,/host/var/lib/docker,/host/snap \
       /host > "$HF" 2>"$HF.err"; then HSUM=$(trivy_sum "$HF"); rm -f "$HF.err"; else HSUM="?|?|?|"; fi
  local krun knew kmsg
  krun=$(uname -r)
  knew=$(ls /boot/vmlinuz-*-"${krun##*-}" 2>/dev/null | sed 's|/boot/vmlinuz-||' | sort -V | tail -1)
  kmsg="running $krun, newest installed ${knew:-?}"
  [[ -n $knew && $knew != "$krun" ]] && kmsg+=" -> REBOOT to activate newer kernel"
  [[ -f /var/run/reboot-required ]] && kmsg+=" | /var/run/reboot-required present ($(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null | cut -c1-120))"
  probe host > "$OUT/probe.txt"; local HPROBE; HPROBE=$(<"$OUT/probe.txt"); rm -f "$OUT/probe.txt"

  # ---------- exit code ----------
  local rc=0 s c h fx kev
  for s in "${SUM[@]}" "$HSUM"; do
    IFS='|' read -r c h fx kev <<<"$s"
    [[ $c =~ ^[0-9]+$ ]] && (( c > 0 && fx > 0 )) && (( rc < 1 )) && rc=1
    [[ -n $kev ]] && rc=2
  done
  (( ${#WATCH[@]} )) && rc=2

  # ---------- report ----------
  {
    echo "Docker / host security audit - $(date '+%F %T %Z') on $(hostname)"
    echo "Trivy: $TRIVY_IMG | $KEVINFO | watchlist: $WATCHLIST"
    echo "Counts are unique CVE ids. FIX = CRITICAL+HIGH with a fixed version available. KEV = in CISA Known Exploited list."
    echo
    echo "== SUMMARY"
    printf '%-30s %-58s %-24s %5s %5s %5s  %s\n' CONTAINER IMAGE UPDATE CRIT HIGH FIX "KEV / WATCHLIST"
    for line in "${INV[@]}"; do
      IFS='|' read -r name ref id state proj files wd svc <<<"$line"
      IFS='|' read -r c h fx kev <<<"${SUM[$id]}"
      local up=
      [[ ${STALE[$ref]} == yes ]] && up+="new-build "
      [[ ${STALE[$ref]} == "?" ]] && up+="unknown "
      [[ -n ${MINOR[$ref]:-} ]] && up+="->${MINOR[$ref]} "
      [[ -n ${MAJOR[$ref]:-} ]] && up+="major:${MAJOR[$ref]} "
      [[ -n ${RESTART[$name]:-} ]] && up+="restart "
      printf '%-30s %-58s %-24s %5s %5s %5s  %s\n' "$name" "$ref" "${up:-current}" "$c" "$h" "$fx" "${kev}${WATCH[$name]:+ WATCH: ${WATCH[$name]}}"
    done
    IFS='|' read -r c h fx kev <<<"$HSUM"
    printf '%-30s %-58s %-24s %5s %5s %5s  %s\n' "HOST $(hostname)" "$(. /etc/os-release; echo "$PRETTY_NAME")" "-" "$c" "$h" "$fx" "${kev}${WATCH[host]:+ WATCH: ${WATCH[host]}}"
    echo
    echo "Legend UPDATE: new-build = same tag rebuilt upstream (pull); ->X = newer patch/minor tag; major:X = newer major (manual);"
    echo "               restart = local tag already points to a newer image than the running container; unknown = registry not reachable"
    echo
    echo "== DETAILS PER CONTAINER"
    for line in "${INV[@]}"; do
      IFS='|' read -r name ref id state proj files wd svc <<<"$line"
      echo "-- $name ($state)"
      echo "   image   : $ref  id ${id:7:12}  ${RNOTE[$ref]:-}"
      if [[ $proj != - ]]; then echo "   compose : project $proj, service $svc, dir $wd"; echo "             files $files"
      else echo "   standalone container (docker run) - recreate command in update.sh"; fi
      echo "   scan    : ${TFILE[$id]}"
      [[ -f ${TFILE[$id]}.err ]] && echo "   SCAN FAILED: $(tail -2 "${TFILE[$id]}.err" | tr '\n' ' ')"
      [[ -f ${TFILE[$id]} ]] && trivy_detail "${TFILE[$id]}"
      echo "   probes  :"; echo "${PROBES[$name]:-    (nothing found)}"
    done
    echo
    echo "== HOST"
    echo "   kernel  : $kmsg"
    echo "   scan    : $HF (OS packages)"
    [[ -f $HF.err ]] && echo "   SCAN FAILED: $(tail -2 "$HF.err" | tr '\n' ' ')"
    [[ -f $HF ]] && trivy_detail "$HF"
    echo "   probes  :"; echo "${HPROBE:-    (nothing found)}"
    echo
    echo "== NEXT STEPS"
    echo "   review and run: $UPD"
    echo "   host packages : sudo apt update && sudo apt full-upgrade, then reboot if the kernel line says so"
  } | tee "$LOG"

  write_update > "$UPD"; chmod +x "$UPD"
  log "report: $LOG"; log "update script: $UPD"
  exit $rc
}

update_header() {
  cat <<'EOF'
#!/usr/bin/env bash
# Generated by docker-audit.sh - REVIEW BEFORE RUNNING. Every block asks for confirmation.
# Compose: patch/minor tag bumps are written into the compose files (backup: <file>.bak-<epoch>), majors are commented out.
set -uo pipefail
confirm() { local a; read -rp "$1 [y/N] " a; [[ $a == [yY] ]]; }
need_env() { local k ok=0; for k; do [[ -v $k ]] || { echo "  export $k=... first (value not copied for safety)"; ok=1; }; done; return $ok; }
# bump OLD NEW FILE..: rewrite "image: OLD" lines (exact ref, optional quotes) to NEW
bump() {
  local old=$1 new=$2 f hit=0; shift 2
  for f; do
    grep -qF "$old" "$f" || continue
    cp -p "$f" "$f.bak-$(date +%s)"
    if awk -v o="$old" -v n="$new" -v q="'" '
      { line=$0
        if (match(line, /^[ \t-]*image:[ \t]*/)) {
          pre=substr(line,1,RLENGTH); rest=substr(line,RLENGTH+1); qt=""; c=substr(rest,1,1)
          if (c=="\"" || c==q) { qt=c; rest=substr(rest,2) }
          if (substr(rest,1,length(o))==o) { tail=substr(rest,length(o)+1); t1=substr(tail,1,1)
            if (tail=="" || t1==" " || t1=="\t" || t1=="#" || t1=="\"" || t1==q) { line=pre qt n tail; hit++ } } }
        print line }
      END { exit hit ? 0 : 1 }' "$f" > "$f.tmp"; then cat "$f.tmp" > "$f"; hit=1; echo "  $f: $old -> $new"; fi
    rm -f "$f.tmp"
  done
  (( hit )) || echo "  WARN: '$old' not found literally in the compose files (tag from a variable like \${VERSION}?) - set it in .env instead"
}
# check_images "svc=image ..." COMPOSE-CMD..: stop if compose would start a service from another image than it runs now
# (e.g. image: app:${VERSION:-latest} started with VERSION exported in a shell that is gone)
check_images() {
  local want=$1 cfg s got bad=0; shift
  cfg=$("$@" config --format json) || return 1
  for s in $want; do
    got=$(jq -r --arg s "${s%%=*}" '.services[$s].image // ""' <<<"$cfg")
    [[ -z $got || $got == "${s#*=}" ]] && continue   # build-only service: compose names the image itself
    echo "  STOP: service ${s%%=*} would run '$got' but runs '${s#*=}' - export the tag variable (e.g. VERSION=...) and retry"; bad=1
  done
  return $bad
}
EOF
}

write_update() {
  update_header
  local key line name ref id state proj files wd svc
  declare -A GROUP=() DONE=()
  for line in "${INV[@]}"; do
    IFS='|' read -r name ref id state proj files wd svc <<<"$line"
    [[ $proj == - ]] || GROUP["$proj|$files|$wd"]+="$ref $name $svc $state "
  done

  for key in "${!GROUP[@]}"; do
    IFS='|' read -r proj files wd <<<"$key"
    local reasons= cmds=() majors=() fargs= qfiles= missing= f r svcs= want= stopped=
    IFS=, read -ra fl <<<"$files"
    for f in "${fl[@]}"; do fargs+=" -f $(q "$f")"; qfiles+=" $(q "$f")"; [[ -f $f ]] || missing+="$f "; done
    DONE=()
    read -ra items <<<"${GROUP[$key]}"
    for ((i=0; i<${#items[@]}; i+=4)); do
      r=${items[i]} name=${items[i+1]}
      # stopped services stay stopped: never pulled into "up"
      if [[ ${items[i+3]} != running ]]; then stopped+="${items[i+2]} "; continue; fi
      svcs+=" $(q "${items[i+2]}")" want+="${items[i+2]}=$r "
      [[ -n ${RESTART[$name]:-} ]] && reasons+="$name runs an older image than local $r; "
      [[ -n ${DONE[$r]:-} ]] && continue; DONE[$r]=1
      split_ref "$r"
      [[ ${STALE[$r]} == yes ]] && reasons+="$r rebuilt upstream; "
      if [[ -n ${MINOR[$r]:-} ]]; then reasons+="$r -> ${MINOR[$r]}; "; cmds+=("bump $(q "$r") $(q "$REPO:${MINOR[$r]}")$qfiles"); fi
      [[ -n ${MAJOR[$r]:-} ]] && majors+=("# bump $(q "$r") $(q "$REPO:${MAJOR[$r]}")$qfiles   # MAJOR: read release notes / migrate data first")
    done
    [[ -z $reasons && ${#majors[@]} == 0 ]] && continue
    echo; echo "# ---- compose project $proj  (dir $wd)"
    echo "#      files: $files"
    echo "#      why  : ${reasons:-only major bumps available}"
    [[ -n $stopped ]] && echo "#      stopped, not touched: $stopped"
    printf '%s\n' "${majors[@]}"
    [[ -z $reasons ]] && continue
    local pre=
    [[ -n $missing ]] && { echo "# SKIPPED - compose file(s) missing: $missing(start the stack the way you did originally)"; pre="# "; }
    echo "${pre}if confirm $(q "Update compose project $proj?"); then"
    echo "${pre}  dc=(docker compose -p $(q "$proj") --project-directory $(q "$wd")$fargs)"
    echo "${pre}  if check_images $(q "${want% }") \"\${dc[@]}\"; then"
    for c in "${cmds[@]}"; do echo "${pre}    $c"; done
    echo "${pre}    \"\${dc[@]}\" pull --ignore-pull-failures$svcs"
    echo "${pre}    \"\${dc[@]}\" up -d --no-deps$svcs   # only the services that run from these files"
    echo "${pre}  fi"
    echo "${pre}fi"
  done

  for line in "${INV[@]}"; do
    IFS='|' read -r name ref id state proj files wd svc <<<"$line"
    [[ $proj == - ]] || continue
    split_ref "$ref"
    local new=$ref why=
    [[ ${STALE[$ref]} == yes ]] && why+="rebuilt upstream; "
    [[ -n ${MINOR[$ref]:-} ]] && { new=$REPO:${MINOR[$ref]}; why+="-> ${MINOR[$ref]}; "; }
    [[ -n ${RESTART[$name]:-} ]] && why+="local tag is newer than running image; "
    echo; echo "# ---- standalone container $name  (image $ref)"
    [[ -n ${MAJOR[$ref]:-} ]] && echo "# MAJOR available: $REPO:${MAJOR[$ref]} - swap it into the run command below manually"
    if [[ -z $why ]]; then echo "# up to date (or registry unreachable) - nothing to do"; continue; fi
    echo "# why: $why"
    echo "# rebuilt from docker inspect: name, restart, network, ports, mounts, env names, labels, entrypoint/cmd."
    echo "# shortcut: caps/devices/user/extra networks are not copied - compare with: docker inspect $name"
    local imgjson envs runcmd verb="run -d" restart="docker start $(q "$name")"
    # stopped containers stay stopped: create, don't run
    [[ $state == running ]] || { verb=create restart=:; }
    imgjson=$(docker image inspect "$id")
    { read -r envs; read -r runcmd; } < <(jq -r --argjson img "$imgjson" --arg new "$new" --arg n "/$name" --arg verb "$verb" '
      .[] | select(.Name==$n) as $c | $img[0].Config as $i | (($c.Config.Env//[]) - ($i.Env//[]) | map(split("=")[0])) as $envs |
      ($envs | join(" ")),
      ((["docker",$verb,"--name",($c.Name|ltrimstr("/")|@sh)]
      + (if ($c.HostConfig.RestartPolicy.Name // "no") | IN("","no") then [] else ["--restart", ($c.HostConfig.RestartPolicy.Name|@sh)] end)
      + (if ($c.HostConfig.NetworkMode // "default") | IN("default","bridge") then [] else ["--network", ($c.HostConfig.NetworkMode|@sh)] end)
      + [($c.HostConfig.PortBindings // {}) | to_entries[] | .key as $p | (.value // [])[] | "-p", ((if (.HostPort//"")=="" then (if (.HostIp//"")!="" then .HostIp+"::" else "" end)
                                   else (if (.HostIp//"")!="" then .HostIp+":" else "" end) + .HostPort + ":" end) + $p | @sh)]
      + [($c.Mounts // [])[] | if .Type=="tmpfs" then "--tmpfs", (.Destination|@sh)
           else "-v", (((if .Type=="volume" then .Name else .Source end) + ":" + .Destination + (if .RW then "" else ":ro" end))|@sh) end]
      + [($c.HostConfig.Tmpfs // {}) | keys[] | "--tmpfs", @sh]
      + [$envs[] | "-e", @sh]
      + [($c.Config.Labels//{}) | to_entries[] | select((($i.Labels//{})[.key]) != .value) | "--label", ("\(.key)=\(.value)"|@sh)]
      + (if $c.Config.Entrypoint != $i.Entrypoint and (($c.Config.Entrypoint//[])|length) > 0 then ["--entrypoint", ($c.Config.Entrypoint[0]|@sh)] else [] end)
      + [$new|@sh]
      + ((if $c.Config.Entrypoint != $i.Entrypoint then (($c.Config.Entrypoint//[])[1:] + ($c.Config.Cmd//[]))
          elif $c.Config.Cmd != $i.Cmd then ($c.Config.Cmd//[]) else [] end) | map(@sh))) | join(" "))' "$OUT/containers.json")
    if [[ -z $runcmd ]]; then echo "# could not rebuild the run command - recreate $name by hand"; continue; fi
    echo "if confirm $(q "Recreate $name from $new?"); then"
    echo "  need_env $envs && docker pull $(q "$new") && docker stop $(q "$name") && docker rename $(q "$name") $(q "$name-old") && {"
    echo "    if $runcmd; then docker rm $(q "$name-old")"
    echo "    else echo 'run failed, restoring old container'; docker rm -f $(q "$name") 2>/dev/null; docker rename $(q "$name-old") $(q "$name"); $restart; fi; }"
    echo "fi"
  done
}

main "$@"
