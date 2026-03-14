#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║              PHANTOM RECON — by Seif                            ║
# ║         Professional Bug Bounty Recon Framework                 ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# MODES:
#   passive   — Zero direct contact. Safe for any target.
#   active    — Controlled probing. Respects rate limits.
#   full      — Complete pipeline. Use with caution.
#   js        — JavaScript analysis only.
#   fuzz      — Directory & parameter fuzzing only.
#
# USAGE:
#   ./recon.sh -d target.com -m passive
#   ./recon.sh -d target.com -m active --threads 5 --rate 15
#   ./recon.sh -d target.com -m full --threads 5 --rate 10 --delay 2
#   ./recon.sh -d target.com -m js
#   ./recon.sh -d target.com -m fuzz --rate 20

# ─────────────────────────────────────────────────────────────────
# DEFAULTS
# ─────────────────────────────────────────────────────────────────
THREADS=5
RATE=10
DELAY=1
MODE=""
TARGET=""
OUTPUT_DIR=""
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

# ─────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ─────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────
banner() {
  echo -e "${PURPLE}"
  echo "  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗"
  echo "  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║"
  echo "  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║"
  echo "  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║"
  echo "  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
  echo "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
  echo -e "${CYAN}              Professional Bug Bounty Recon Framework${RESET}"
  echo -e "${YELLOW}              Modes: passive | active | full | js | fuzz${RESET}"
  echo ""
}

# ─────────────────────────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[+]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }
section() { echo -e "\n${BOLD}${PURPLE}━━━ $1 ━━━${RESET}"; }

# ─────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage:${RESET}"
  echo "  $0 -d <domain> -m <mode> [options]"
  echo ""
  echo -e "${BOLD}Modes:${RESET}"
  echo "  passive   Zero direct contact — safe always"
  echo "  active    Controlled probing with rate limits"
  echo "  full      Complete recon pipeline"
  echo "  js        JavaScript analysis only"
  echo "  fuzz      Directory & parameter fuzzing only"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo "  -d, --domain      Target domain (required)"
  echo "  -m, --mode        Recon mode (required)"
  echo "  -t, --threads     Thread count (default: 5)"
  echo "  -r, --rate        Requests per second (default: 10)"
  echo "  --delay           Seconds between tool runs (default: 1)"
  echo "  -w, --wordlist    Custom wordlist path"
  echo "  -h, --help        Show this help"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  $0 -d target.com -m passive"
  echo "  $0 -d target.com -m active -t 5 -r 15"
  echo "  $0 -d target.com -m full -t 5 -r 10 --delay 2"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--domain)   TARGET="$2";    shift 2 ;;
    -m|--mode)     MODE="$2";      shift 2 ;;
    -t|--threads)  THREADS="$2";   shift 2 ;;
    -r|--rate)     RATE="$2";      shift 2 ;;
    --delay)       DELAY="$2";     shift 2 ;;
    -w|--wordlist) WORDLIST="$2";  shift 2 ;;
    -h|--help)     usage ;;
    *) error "Unknown argument: $1"; usage ;;
  esac
done

# ─────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────
validate() {
  [[ -z "$TARGET" ]] && { error "Target domain required. Use -d target.com"; exit 1; }
  [[ -z "$MODE" ]]   && { error "Mode required. Use -m passive|active|full|js|fuzz"; exit 1; }

  case $MODE in
    passive|active|full|js|fuzz) ;;
    *) error "Invalid mode: $MODE"; exit 1 ;;
  esac

  # Check required tools per mode
  check_tool() {
    command -v "$1" &>/dev/null || warn "Tool not found: $1 — install with: yay -S $1"
  }

  check_tool subfinder
  check_tool httpx

  [[ "$MODE" != "passive" ]] && check_tool amass
  [[ "$MODE" == "js" || "$MODE" == "full" ]] && check_tool gau
  [[ "$MODE" == "fuzz" || "$MODE" == "full" ]] && check_tool ffuf
}

# ─────────────────────────────────────────────────────────────────
# SETUP OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────
setup_output() {
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  OUTPUT_DIR="phantom_${TARGET}_${TIMESTAMP}"
  mkdir -p "$OUTPUT_DIR"/{subdomains,urls,js,fuzzing,reports}
  info "Output directory: ${BOLD}$OUTPUT_DIR${RESET}"
  info "Mode: ${BOLD}${YELLOW}$MODE${RESET} | Threads: $THREADS | Rate: $RATE req/s | Delay: ${DELAY}s"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 1 — PASSIVE SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────
passive_subs() {
  section "PASSIVE SUBDOMAIN ENUMERATION"
  warn "No direct contact with target — safe mode"

  info "Running subfinder (passive)..."
  subfinder -d "$TARGET" \
    -o "$OUTPUT_DIR/subdomains/subfinder.txt" \
    -t "$THREADS" \
    -timeout 30 \
    -silent 2>/dev/null
  success "subfinder done: $(wc -l < "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) results"

  sleep "$DELAY"

  info "Running amass (passive only — no active probing)..."
  amass enum \
    --passive \
    -d "$TARGET" \
    -o "$OUTPUT_DIR/subdomains/amass.txt" \
    -timeout 10 2>/dev/null
  success "amass done: $(wc -l < "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) results"

  sleep "$DELAY"

  # Merge & deduplicate
  cat "$OUTPUT_DIR/subdomains/"*.txt 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/subdomains/all_subs.txt"

  success "Total unique subdomains: ${BOLD}$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt")${RESET}"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 2 — PROBE ALIVE HOSTS (controlled)
# ─────────────────────────────────────────────────────────────────
probe_alive() {
  section "PROBING ALIVE HOSTS"
  warn "Rate limited to $RATE req/s with $THREADS threads"

  [[ ! -f "$OUTPUT_DIR/subdomains/all_subs.txt" ]] && {
    error "No subdomains file found. Run passive mode first."
    return
  }

  info "Probing with httpx..."
  cat "$OUTPUT_DIR/subdomains/all_subs.txt" | httpx \
    -threads "$THREADS" \
    -rate-limit "$RATE" \
    -timeout 10 \
    -status-code \
    -title \
    -tech-detect \
    -o "$OUTPUT_DIR/subdomains/alive.txt" \
    -silent 2>/dev/null

  success "Alive hosts: ${BOLD}$(wc -l < "$OUTPUT_DIR/subdomains/alive.txt")${RESET}"

  sleep "$DELAY"

  # Extract interesting status codes separately
  grep " \[403\]" "$OUTPUT_DIR/subdomains/alive.txt" > \
    "$OUTPUT_DIR/subdomains/403_hosts.txt" 2>/dev/null
  grep " \[401\]" "$OUTPUT_DIR/subdomains/alive.txt" > \
    "$OUTPUT_DIR/subdomains/401_hosts.txt" 2>/dev/null

  success "403 hosts (potential bypass targets): $(wc -l < "$OUTPUT_DIR/subdomains/403_hosts.txt" 2>/dev/null || echo 0)"
  success "401 hosts (auth protected): $(wc -l < "$OUTPUT_DIR/subdomains/401_hosts.txt" 2>/dev/null || echo 0)"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 3 — URL HARVESTING (passive, historical)
# ─────────────────────────────────────────────────────────────────
harvest_urls() {
  section "URL HARVESTING (historical — passive)"

  [[ ! -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && {
    error "No alive hosts file found. Run active mode first."
    return
  }

  info "Fetching historical URLs via gau (wayback + otx + commoncrawl)..."
  cat "$OUTPUT_DIR/subdomains/alive.txt" | \
    awk '{print $1}' | \
    gau \
      --threads 2 \
      --timeout 30 \
      --blacklist png,jpg,gif,svg,ico,css,woff,woff2,ttf \
    > "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null

  success "Total URLs harvested: ${BOLD}$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")${RESET}"

  sleep "$DELAY"

  # Categorize URLs
  grep "\.js"        "$OUTPUT_DIR/urls/all_urls.txt" | sort -u > "$OUTPUT_DIR/urls/js_urls.txt"
  grep "\.json"      "$OUTPUT_DIR/urls/all_urls.txt" | sort -u > "$OUTPUT_DIR/urls/json_urls.txt"
  grep "/api/"       "$OUTPUT_DIR/urls/all_urls.txt" | sort -u > "$OUTPUT_DIR/urls/api_urls.txt"
  grep "\.php\|\.asp\|\.aspx\|\.jsp" \
                     "$OUTPUT_DIR/urls/all_urls.txt" | sort -u > "$OUTPUT_DIR/urls/dynamic_urls.txt"
  grep "redirect\|url=\|next=\|return=\|redir=" \
                     "$OUTPUT_DIR/urls/all_urls.txt" | sort -u > "$OUTPUT_DIR/urls/redirect_params.txt"

  success "JS files:          $(wc -l < "$OUTPUT_DIR/urls/js_urls.txt")"
  success "JSON endpoints:    $(wc -l < "$OUTPUT_DIR/urls/json_urls.txt")"
  success "API paths:         $(wc -l < "$OUTPUT_DIR/urls/api_urls.txt")"
  success "Dynamic pages:     $(wc -l < "$OUTPUT_DIR/urls/dynamic_urls.txt")"
  success "Redirect params:   $(wc -l < "$OUTPUT_DIR/urls/redirect_params.txt")"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 4 — JAVASCRIPT ANALYSIS
# ─────────────────────────────────────────────────────────────────
analyze_js() {
  section "JAVASCRIPT ANALYSIS"

  JS_FILE="$OUTPUT_DIR/urls/js_urls.txt"
  [[ ! -f "$JS_FILE" ]] && {
    error "No JS URLs file. Run harvest_urls first or use -m full"
    return
  }

  info "Downloading and analyzing JS files..."
  mkdir -p "$OUTPUT_DIR/js/files"

  # Download JS files with rate limiting
  while IFS= read -r jsurl; do
    filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1)
    curl -s \
      --max-time 10 \
      --limit-rate 50k \
      -o "$OUTPUT_DIR/js/files/${filename}.js" \
      "$jsurl" 2>/dev/null
    sleep 0.5  # gentle delay between downloads
  done < "$JS_FILE"

  success "Downloaded JS files"
  sleep "$DELAY"

  # Extract endpoints from JS files
  info "Extracting endpoints from JS files..."
  grep -rhoE "(https?://[a-zA-Z0-9./?=_%:-]*|/[a-zA-Z0-9/_-]+)" \
    "$OUTPUT_DIR/js/files/" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/js/endpoints.txt"

  # Look for sensitive patterns
  info "Scanning for sensitive data in JS..."
  grep -rhoiE \
    "(api[_-]?key|apikey|secret|token|password|passwd|auth|bearer|aws_|s3_bucket|firebase)" \
    "$OUTPUT_DIR/js/files/" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/js/sensitive_keywords.txt"

  # Look for hardcoded credentials pattern
  grep -rhoiE \
    "(['\"][a-zA-Z0-9_-]{20,}['\"])" \
    "$OUTPUT_DIR/js/files/" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/js/potential_tokens.txt"

  success "Endpoints found in JS:    $(wc -l < "$OUTPUT_DIR/js/endpoints.txt")"
  success "Sensitive keywords:       $(wc -l < "$OUTPUT_DIR/js/sensitive_keywords.txt")"
  success "Potential tokens/keys:    $(wc -l < "$OUTPUT_DIR/js/potential_tokens.txt")"

  warn "Manually review: $OUTPUT_DIR/js/sensitive_keywords.txt"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 5 — FUZZING (rate limited)
# ─────────────────────────────────────────────────────────────────
fuzz_targets() {
  section "DIRECTORY & PARAMETER FUZZING"
  warn "Rate limited — $RATE req/s max. Review program policy before fuzzing."

  [[ ! -f "$WORDLIST" ]] && {
    error "Wordlist not found: $WORDLIST"
    error "Install seclists: yay -S seclists"
    return
  }

  [[ ! -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && {
    error "No alive hosts. Run active mode first."
    return
  }

  info "Fuzzing alive hosts for hidden directories..."
  mkdir -p "$OUTPUT_DIR/fuzzing"

  while IFS= read -r host; do
    domain=$(echo "$host" | awk '{print $1}')
    safe_name=$(echo "$domain" | sed 's/[:/]/_/g')

    info "Fuzzing: $domain"
    ffuf \
      -u "${domain}/FUZZ" \
      -w "$WORDLIST" \
      -t "$THREADS" \
      -rate "$RATE" \
      -timeout 10 \
      -mc 200,201,301,302,401,403 \
      -o "$OUTPUT_DIR/fuzzing/${safe_name}.json" \
      -of json \
      -s 2>/dev/null

    sleep "$DELAY"

  done < "$OUTPUT_DIR/subdomains/alive.txt"

  success "Fuzzing complete. Results in $OUTPUT_DIR/fuzzing/"
  warn "Review 401/403 results for bypass opportunities"
}

# ─────────────────────────────────────────────────────────────────
# FINAL REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────
generate_report() {
  section "GENERATING REPORT"

  REPORT="$OUTPUT_DIR/reports/summary.txt"

  {
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║           PHANTOM RECON — SUMMARY REPORT            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "Target:     $TARGET"
    echo "Mode:       $MODE"
    echo "Date:       $(date)"
    echo "Output:     $OUTPUT_DIR"
    echo ""
    echo "─────────────────── RESULTS ───────────────────"
    echo ""

    [[ -f "$OUTPUT_DIR/subdomains/all_subs.txt" ]] && \
      echo "Total subdomains:        $(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt")"

    [[ -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && \
      echo "Alive hosts:             $(wc -l < "$OUTPUT_DIR/subdomains/alive.txt")"

    [[ -f "$OUTPUT_DIR/subdomains/403_hosts.txt" ]] && \
      echo "403 hosts (bypass?):     $(wc -l < "$OUTPUT_DIR/subdomains/403_hosts.txt")"

    [[ -f "$OUTPUT_DIR/subdomains/401_hosts.txt" ]] && \
      echo "401 hosts (auth):        $(wc -l < "$OUTPUT_DIR/subdomains/401_hosts.txt")"

    [[ -f "$OUTPUT_DIR/urls/all_urls.txt" ]] && \
      echo "Total URLs:              $(wc -l < "$OUTPUT_DIR/urls/all_urls.txt")"

    [[ -f "$OUTPUT_DIR/urls/api_urls.txt" ]] && \
      echo "API endpoints:           $(wc -l < "$OUTPUT_DIR/urls/api_urls.txt")"

    [[ -f "$OUTPUT_DIR/urls/redirect_params.txt" ]] && \
      echo "Redirect params:         $(wc -l < "$OUTPUT_DIR/urls/redirect_params.txt")"

    [[ -f "$OUTPUT_DIR/js/sensitive_keywords.txt" ]] && \
      echo "JS sensitive keywords:   $(wc -l < "$OUTPUT_DIR/js/sensitive_keywords.txt")"

    echo ""
    echo "─────────────────── NEXT STEPS ────────────────"
    echo ""
    echo "1. Review $OUTPUT_DIR/subdomains/403_hosts.txt — try 403 bypass"
    echo "2. Review $OUTPUT_DIR/urls/api_urls.txt       — test for auth issues"
    echo "3. Review $OUTPUT_DIR/js/sensitive_keywords.txt — check for leaked keys"
    echo "4. Review $OUTPUT_DIR/urls/redirect_params.txt — test open redirect"
    echo "5. Apply OAuth & Access Control knowledge on alive hosts"
    echo ""
  } > "$REPORT"

  cat "$REPORT"
}

# ─────────────────────────────────────────────────────────────────
# MODE RUNNERS
# ─────────────────────────────────────────────────────────────────
run_passive() {
  passive_subs
  generate_report
}

run_active() {
  passive_subs
  probe_alive
  generate_report
}

run_full() {
  passive_subs
  probe_alive
  harvest_urls
  analyze_js
  fuzz_targets
  generate_report
}

run_js() {
  harvest_urls
  analyze_js
  generate_report
}

run_fuzz() {
  fuzz_targets
  generate_report
}

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
main() {
  banner
  validate
  setup_output

  case $MODE in
    passive) run_passive ;;
    active)  run_active  ;;
    full)    run_full    ;;
    js)      run_js      ;;
    fuzz)    run_fuzz    ;;
  esac

  echo ""
  success "Phantom Recon complete. All output saved to: ${BOLD}$OUTPUT_DIR${RESET}"
}

main
