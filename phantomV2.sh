#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║              PHANTOM RECON — by Seif                            ║
# ║         Professional Bug Bounty Recon Framework                 ║
# ║                     v2.0                                        ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# CHANGELOG v2.0:
#   - amass: added -max-dns-queries rate limiting
#   - JS analysis: upgraded to gf patterns + trufflehog entropy scan
#   - URL cleaning: added uro deduplication + extended grep -v filter
#   - Rate limiting: clarified per-tool enforcement in comments
#
# MODES:
#   passive   — Zero direct contact. Safe for any target.
#   active    — Controlled probing. Respects rate limits.
#   full      — Complete pipeline. Use with caution.
#   js        — JavaScript analysis only.
#   fuzz      — Directory & parameter fuzzing only.
#
# USAGE:
#   ./phantom.sh -d target.com -m passive
#   ./phantom.sh -d target.com -m active --threads 5 --rate 15
#   ./phantom.sh -d target.com -m full --threads 5 --rate 10 --delay 2
#   ./phantom.sh -d target.com -m js
#   ./phantom.sh -d target.com -m fuzz --rate 20

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
MAX_DNS_QUERIES=200   # amass rate limiter
# ─────────────────────────────────────────────────────────────────
# TOOL PATHS
# ─────────────────────────────────────────────────────────────────
# The LinkFinder venv we just created
LINKFINDER_BIN="$HOME/tools/LinkFinder/venv/bin/python $HOME/tools/LinkFinder/linkfinder.py"
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
  echo -e "${CYAN}           Professional Bug Bounty Recon Framework — v2.0${RESET}"
  echo -e "${YELLOW}           Modes: passive | active | full | js | fuzz${RESET}"
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
  echo "  -d, --domain        Target domain (required)"
  echo "  -m, --mode          Recon mode (required)"
  echo "  -t, --threads       Thread count (default: 5)"
  echo "  -r, --rate          Requests per second (default: 10)"
  echo "  --delay             Seconds between tool runs (default: 1)"
  echo "  --max-dns           Max DNS queries for amass (default: 200)"
  echo "  -w, --wordlist      Custom wordlist path"
  echo "  -h, --help          Show this help"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  $0 -d target.com -m passive"
  echo "  $0 -d target.com -m active -t 5 -r 15"
  echo "  $0 -d target.com -m full -t 5 -r 10 --delay 2 --max-dns 100"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--domain)    TARGET="$2";           shift 2 ;;
    -m|--mode)      MODE="$2";             shift 2 ;;
    -t|--threads)   THREADS="$2";          shift 2 ;;
    -r|--rate)      RATE="$2";             shift 2 ;;
    --delay)        DELAY="$2";            shift 2 ;;
    --max-dns)      MAX_DNS_QUERIES="$2";  shift 2 ;;
    -w|--wordlist)  WORDLIST="$2";         shift 2 ;;
    -h|--help)      usage ;;
    *) error "Unknown argument: $1"; usage ;;
  esac
done

# ─────────────────────────────────────────────────────────────────
# NEW UTILITY: SUBDOMAIN CLEANER
# ─────────────────────────────────────────────────────────────────
clean_subs() {
  local raw_file="$1"
  local clean_file="$2"
  
  info "Cleaning and validating subdomains for $TARGET..."
  
  grep -oE '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' "$raw_file" | \
    tr '[:upper:]' '[:lower:]' | \
    grep -E "(\.|^)${TARGET}$" | \
    grep -vE '(ns-[0-9]+\.awsdns|awsdns|_record|fqdn|-->|aka\.ms|amazonaws|azure)' | \
    sort -u > "$clean_file"

  success "Cleaning complete. Valid targets: $(wc -l < "$clean_file")"
}
# ─────────────────────────────────────────────────────────────────
# TOOL CHECK HELPER
# ─────────────────────────────────────────────────────────────────
check_tool() {
  local tool=$1
  local install_hint=${2:-"yay -S $tool"}
  if ! command -v "$tool" &>/dev/null; then
    warn "Tool not found: ${BOLD}$tool${RESET} — install: $install_hint"
    return 1
  fi
  return 0
}

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

  # Core tools — always required
  check_tool subfinder
  check_tool httpx-toolkit


  # Mode-specific tools
  case $MODE in
    passive|active|full)
      check_tool amass
      ;;
  esac

  case $MODE in
    js|full)
      check_tool gau
      check_tool trufflehog "go install github.com/trufflesecurity/trufflehog/v3@latest"
      # gf is optional — warn only
      command -v gf &>/dev/null || warn "gf not found (optional but recommended) — install: go install github.com/tomnomnom/gf@latest"
      # uro is optional — warn only
      command -v uro &>/dev/null || warn "uro not found (optional but recommended) — install: pip install uro"
      ;;
  esac

  case $MODE in
    fuzz|full)
      check_tool ffuf
      ;;
  esac
}

# ─────────────────────────────────────────────────────────────────
# SETUP OUTPUT DIRECTORY
# ─────────────────────────────────────────────────────────────────
setup_output() {
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  OUTPUT_DIR="phantom_${TARGET}_${TIMESTAMP}"
  mkdir -p "$OUTPUT_DIR"/{subdomains,urls,js/files,fuzzing,reports}
  info "Output directory: ${BOLD}$OUTPUT_DIR${RESET}"
  info "Mode: ${BOLD}${YELLOW}$MODE${RESET} | Threads: $THREADS | Rate: $RATE req/s | Delay: ${DELAY}s | Max DNS: $MAX_DNS_QUERIES"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 1 — PASSIVE SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────
# Rate limiting:
#   subfinder → -t (thread cap, passive sources only, safe)
#   amass     → --passive + -max-dns-queries (hard cap on DNS queries per minute)
# ─────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
# MODULE 1 — PASSIVE SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────
passive_subs() {
  section "PASSIVE SUBDOMAIN ENUMERATION"
  warn "No direct contact with target — passive sources only"

  info "Running subfinder..."
  subfinder -d "$TARGET" \
    -o "$OUTPUT_DIR/subdomains/subfinder.txt" \
    -t "$THREADS" \
    -timeout 30 \
    -silent 2>/dev/null
  success "subfinder: $(wc -l < "$OUTPUT_DIR/subdomains/subfinder.txt" 2>/dev/null || echo 0) results"

  sleep "$DELAY"

  info "Running amass (passive)..."
  amass enum \
    --passive \
    -d "$TARGET" \
    -o "$OUTPUT_DIR/subdomains/amass.txt" \
    -max-dns-queries "$MAX_DNS_QUERIES" \
    -timeout 15 2>/dev/null
  success "amass: $(wc -l < "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null || echo 0) results"

  sleep "$DELAY"

  # --- THIS IS THE NEW PART ---
  info "Merging and cleaning subdomain lists..."
  cat "$OUTPUT_DIR/subdomains/subfinder.txt" "$OUTPUT_DIR/subdomains/amass.txt" 2>/dev/null > "$OUTPUT_DIR/subdomains/raw_combined.txt"

  # Call your clean_subs function
  clean_subs "$OUTPUT_DIR/subdomains/raw_combined.txt" "$OUTPUT_DIR/subdomains/all_subs.txt"
  
  # Remove the messy combined file
  rm "$OUTPUT_DIR/subdomains/raw_combined.txt"
  # ----------------------------

  success "Total unique subdomains: ${BOLD}$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt")${RESET}"
}
# ─────────────────────────────────────────────────────────────────
# MODULE 2 — PROBE ALIVE HOSTS
# ─────────────────────────────────────────────────────────────────
# Rate limiting:
#   httpx-toolkit → -rate-limit (native, requests/sec) + -threads (concurrency cap)
#   Both enforced natively by httpx-toolkit — not bash sleep
# ─────────────────────────────────────────────────────────────────
probe_alive() {
  section "PROBING ALIVE HOSTS"
  warn "Direct contact — rate limited: $RATE req/s / $THREADS threads (httpx-toolkit native)"

  [[ ! -f "$OUTPUT_DIR/subdomains/all_subs.txt" ]] && {
    error "No subdomains file. Run passive mode first."
    return 1
  }

  info "Probing with httpx-toolkit..."
  cat "$OUTPUT_DIR/subdomains/all_subs.txt" | httpx-toolkit \
    -threads "$THREADS" \
    -rate-limit "$RATE" \
    -timeout 10 \
    -status-code \
    -title \
    -tech-detect \
    -follow-redirects \
    -o "$OUTPUT_DIR/subdomains/alive.txt" \
    -silent 2>/dev/null

  success "Alive hosts: ${BOLD}$(wc -l < "$OUTPUT_DIR/subdomains/alive.txt")${RESET}"

  sleep "$DELAY"

  # Separate by status code — each is a different attack surface
  grep "\[200\]" "$OUTPUT_DIR/subdomains/alive.txt" > "$OUTPUT_DIR/subdomains/200_hosts.txt" 2>/dev/null
  grep "\[403\]" "$OUTPUT_DIR/subdomains/alive.txt" > "$OUTPUT_DIR/subdomains/403_hosts.txt" 2>/dev/null
  grep "\[401\]" "$OUTPUT_DIR/subdomains/alive.txt" > "$OUTPUT_DIR/subdomains/401_hosts.txt" 2>/dev/null
  grep "\[302\]\|\[301\]" "$OUTPUT_DIR/subdomains/alive.txt" > "$OUTPUT_DIR/subdomains/redirect_hosts.txt" 2>/dev/null

  success "200 hosts:                $(wc -l < "$OUTPUT_DIR/subdomains/200_hosts.txt" 2>/dev/null || echo 0)"
  success "403 hosts (bypass?):      $(wc -l < "$OUTPUT_DIR/subdomains/403_hosts.txt" 2>/dev/null || echo 0)"
  success "401 hosts (auth wall):    $(wc -l < "$OUTPUT_DIR/subdomains/401_hosts.txt" 2>/dev/null || echo 0)"
  success "Redirect hosts:           $(wc -l < "$OUTPUT_DIR/subdomains/redirect_hosts.txt" 2>/dev/null || echo 0)"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 3 — URL HARVESTING + CLEANING
# ─────────────────────────────────────────────────────────────────
# FIX v2.0:
#   - Extended blacklist on gau itself (static assets)
#   - Post-harvest cleaning pipeline: grep -vE + uro deduplication
#   - uro removes duplicate paths with different param values
#   - Result: clean_urls.txt is what all downstream modules use
# ─────────────────────────────────────────────────────────────────
harvest_urls() {
  section "URL HARVESTING + CLEANING"

  [[ ! -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && {
    error "No alive hosts file. Run active mode first."
    return 1
  }

  info "Fetching historical URLs via gau (wayback + otx + commoncrawl)..."
  # gau rate limited via --threads 2 (intentionally low)
  awk '{print $1}' "$OUTPUT_DIR/subdomains/alive.txt" | \
    gau \
      --threads 2 \
      --timeout 30 \
      --blacklist png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,pdf,zip,tar,gz \
    > "$OUTPUT_DIR/urls/raw_urls.txt" 2>/dev/null

  success "Raw URLs harvested: $(wc -l < "$OUTPUT_DIR/urls/raw_urls.txt")"
  sleep "$DELAY"

  # ── CLEANING PIPELINE ──────────────────────────────────────────
  info "Cleaning URLs — removing noise and deduplicating..."

  # Step 1: Extended static asset + tracker filter
  grep -vE \
    "\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz|map)(\?|$)" \
    "$OUTPUT_DIR/urls/raw_urls.txt" | \
  grep -vE \
    "(google-analytics|googletagmanager|doubleclick|facebook\.com/tr|twitter\.com/i/|cdn\.jsdelivr|cloudflare)" | \
  sort -u > "$OUTPUT_DIR/urls/filtered_urls.txt"

  # Step 2: uro deduplication (removes param variations of same path)
  # e.g. /page?id=1 and /page?id=2 → keeps one
  if command -v uro &>/dev/null; then
    info "Running uro deduplication..."
    uro -i "$OUTPUT_DIR/urls/filtered_urls.txt" \
        -o "$OUTPUT_DIR/urls/clean_urls.txt" 2>/dev/null
    success "After uro dedup: $(wc -l < "$OUTPUT_DIR/urls/clean_urls.txt") URLs"
  else
    warn "uro not found — skipping deduplication. Install: pip install uro"
    cp "$OUTPUT_DIR/urls/filtered_urls.txt" "$OUTPUT_DIR/urls/clean_urls.txt"
  fi

  # ── CATEGORIZATION (from clean_urls.txt) ──────────────────────
  info "Categorizing clean URLs..."

  grep -E "\.js(\?|$)"     "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/js_urls.txt"
  grep -E "\.json(\?|$)"   "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/json_urls.txt"
  grep -E "/api/"           "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/api_urls.txt"
  grep -E "\.(php|asp|aspx|jsp)(\?|$)" \
                             "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/dynamic_urls.txt"
  grep -iE "[?&](redirect|url|next|return|redir|dest|destination|target|goto)=" \
                             "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/redirect_params.txt"
  grep -iE "[?&](id|user|uid|account|order|invoice|file|doc|report)=" \
                             "$OUTPUT_DIR/urls/clean_urls.txt" | sort -u > "$OUTPUT_DIR/urls/idor_params.txt"

  success "Clean URLs total:    $(wc -l < "$OUTPUT_DIR/urls/clean_urls.txt")"
  success "JS files:            $(wc -l < "$OUTPUT_DIR/urls/js_urls.txt")"
  success "JSON endpoints:      $(wc -l < "$OUTPUT_DIR/urls/json_urls.txt")"
  success "API paths:           $(wc -l < "$OUTPUT_DIR/urls/api_urls.txt")"
  success "Dynamic pages:       $(wc -l < "$OUTPUT_DIR/urls/dynamic_urls.txt")"
  success "Redirect params:     $(wc -l < "$OUTPUT_DIR/urls/redirect_params.txt")"
  success "IDOR candidates:     $(wc -l < "$OUTPUT_DIR/urls/idor_params.txt")"
}

# ─────────────────────────────────────────────────────────────────
# MODULE 4 — JAVASCRIPT ANALYSIS
# ─────────────────────────────────────────────────────────────────
# FIX v2.0:
#   Layer 1 — grep regex (fast, keyword-based, catches obvious secrets)
#   Layer 2 — gf patterns (curated regex for JWT, AWS, Google, Slack etc.)
#   Layer 3 — trufflehog entropy scan (catches high-entropy strings
#              that have no obvious keyword — the ones grep misses)
# ─────────────────────────────────────────────────────────────────
analyze_js() {
  section "JAVASCRIPT ANALYSIS"

  # Path to the venv python we created earlier
  LINKFINDER_BIN="$HOME/tools/LinkFinder/venv/bin/python $HOME/tools/LinkFinder/linkfinder.py"

  JS_FILE="$OUTPUT_DIR/urls/js_urls.txt"
  [[ ! -f "$JS_FILE" ]] && {
    error "No JS URLs file. Run harvest_urls first or use -m full"
    return 1
  }

  local js_count
  js_count=$(wc -l < "$JS_FILE")
  info "Found $js_count JS files to analyze"

  # ── DOWNLOAD JS FILES ─────────────────────────────────────────
  info "Downloading JS files (rate limited: 0.5s delay, 50kb/s)..."
  local downloaded=0

  while IFS= read -r jsurl; do
    [[ -z "$jsurl" ]] && continue
    filename=$(echo "$jsurl" | md5sum | cut -d' ' -f1)
    outfile="$OUTPUT_DIR/js/files/${filename}.js"

    [[ -f "$outfile" ]] && continue

    curl -s \
      --max-time 10 \
      --limit-rate 50k \
      -A "Mozilla/5.0 (compatible; recon-bot/1.0)" \
      -o "$outfile" \
      "$jsurl" 2>/dev/null

    ((downloaded++))
    sleep 0.5   
  done < "$JS_FILE"

  success "Downloaded: $downloaded JS files"
  sleep "$DELAY"

  # ── LAYER 1: LinkFinder & Keyword Grep ───────────────────────
  # UPGRADE: Using LinkFinder instead of basic regex for endpoint discovery
  info "[Layer 1] LinkFinder — Deep endpoint extraction..."
  $LINKFINDER_BIN -i "$OUTPUT_DIR/js/files/*.js" -o cli > "$OUTPUT_DIR/js/endpoints.txt" 2>/dev/null

  info "[Layer 1] grep — keyword pattern matching for secrets..."
  grep -rhoiE \
    "(api[_-]?key|apikey|api_secret|app_secret|client_secret|access_token|auth_token|bearer|password|passwd|private_key|aws_access|aws_secret|s3_bucket|firebase|twilio|stripe|sendgrid|github_token|slack_token|heroku)" \
    "$OUTPUT_DIR/js/files/" 2>/dev/null | \
    sort -u > "$OUTPUT_DIR/js/grep_keywords.txt"

  success "[Layer 1] Endpoints extracted: $(wc -l < "$OUTPUT_DIR/js/endpoints.txt" 2>/dev/null || echo 0)"
  success "[Layer 1] Keywords found:      $(wc -l < "$OUTPUT_DIR/js/grep_keywords.txt" 2>/dev/null || echo 0)"

  # ── LAYER 2: gf — curated pattern sets ───────────────────────
  if command -v gf &>/dev/null; then
    info "[Layer 2] gf — curated pattern scanning..."
    mkdir -p "$OUTPUT_DIR/js/gf"

    for pattern in aws-keys base64 debug-pages firebase go-lang http-auth \
                   ip-addresses js-vars json-sec jwt mg-api php-errors \
                   possible-creds r-and-d-functions redirect secrets \
                   s3-buckets servers strings-urls takeovers upload-fields; do
      gf "$pattern" "$OUTPUT_DIR/js/files/"* 2>/dev/null | \
        sort -u > "$OUTPUT_DIR/js/gf/${pattern}.txt"
      [[ ! -s "$OUTPUT_DIR/js/gf/${pattern}.txt" ]] && \
        rm -f "$OUTPUT_DIR/js/gf/${pattern}.txt"
    done

    local gf_hits
    gf_hits=$(cat "$OUTPUT_DIR/js/gf/"*.txt 2>/dev/null | sort -u | wc -l)
    success "[Layer 2] gf total hits:    $gf_hits across all patterns"
  else
    warn "[Layer 2] gf not found — skipping pattern scan"
  fi

  # ── LAYER 3: trufflehog — entropy analysis ────────────────────
  if command -v trufflehog &>/dev/null; then
    info "[Layer 3] trufflehog — entropy-based secret detection..."
    trufflehog filesystem \
      "$OUTPUT_DIR/js/files/" \
      --json \
      --no-update \
      2>/dev/null > "$OUTPUT_DIR/js/trufflehog_results.json"

    local th_count
    th_count=$(grep -c '"SourceMetadata"' "$OUTPUT_DIR/js/trufflehog_results.json" 2>/dev/null || echo 0)
    success "[Layer 3] trufflehog hits:  $th_count high-entropy secrets found"

    if [[ "$th_count" -gt 0 ]]; then
      warn "HIGH PRIORITY: Review $OUTPUT_DIR/js/trufflehog_results.json"
    fi
  else
    warn "[Layer 3] trufflehog not found — skipping entropy scan"
  fi

  success "JS analysis complete — review $OUTPUT_DIR/js/"
}
# ─────────────────────────────────────────────────────────────────
# MODULE 5 — FUZZING
# ─────────────────────────────────────────────────────────────────
# Rate limiting:
#   ffuf → -rate (native req/s cap) + -t (thread cap)
#   Both enforced natively by ffuf — most reliable method
#   bash sleep between hosts = additional politeness buffer
# ─────────────────────────────────────────────────────────────────
fuzz_targets() {
  section "DIRECTORY & PARAMETER FUZZING"
  warn "Stealth Mode: Using delays to avoid detection on $TARGET"

  # ... [Keep your wordlist and alive.txt checks] ...

  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    domain=$(echo "$host" | awk '{print $1}')
    safe_name=$(echo "$domain" | sed 's/[:/]/_/g')

    info "Fuzzing: $domain"
    
    # -p 0.1-0.5: Adds a random delay between 100ms and 500ms (looks human)
    # -rate 3: Hard limit of 3 requests per second
    # -t 2: Low thread count to keep the connection "thin"
    ffuf -u "${domain}/FUZZ" \
      -w "$WORDLIST" \
      -t 2 \
      -p "0.1-0.5" \
      -rate 3 \
      -timeout 10 \
      -mc 200,201,204,301,302,401,403,405 \
      -fc 404 \
      -ac \
      -o "$OUTPUT_DIR/fuzzing/${safe_name}.json" \
      -of json \
      -s

    # A longer "breather" between different subdomains
    sleep 2
  done < "$OUTPUT_DIR/subdomains/alive.txt"


  success "Fuzzing complete — results in $OUTPUT_DIR/fuzzing/"
  warn "Focus on 401/403 results — potential bypass opportunities"
}

# ─────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────
generate_report() {
  section "GENERATING REPORT"

  REPORT="$OUTPUT_DIR/reports/summary.txt"
  TH_HITS=$(grep -c '"SourceMetadata"' "$OUTPUT_DIR/js/trufflehog_results.json" 2>/dev/null || echo 0)

  {
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║         PHANTOM RECON v2.0 — SUMMARY REPORT         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "Target:       $TARGET"
    echo "Mode:         $MODE"
    echo "Date:         $(date)"
    echo "Threads:      $THREADS  |  Rate: $RATE req/s  |  Delay: ${DELAY}s"
    echo "Output dir:   $OUTPUT_DIR"
    echo ""
    echo "──────────────────── SUBDOMAINS ────────────────────────"
    [[ -f "$OUTPUT_DIR/subdomains/all_subs.txt" ]]      && echo "  Total found:         $(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt")"
    [[ -f "$OUTPUT_DIR/subdomains/alive.txt" ]]         && echo "  Alive hosts:         $(wc -l < "$OUTPUT_DIR/subdomains/alive.txt")"
    [[ -f "$OUTPUT_DIR/subdomains/200_hosts.txt" ]]     && echo "  200 OK:              $(wc -l < "$OUTPUT_DIR/subdomains/200_hosts.txt")"
    [[ -f "$OUTPUT_DIR/subdomains/403_hosts.txt" ]]     && echo "  403 Forbidden:       $(wc -l < "$OUTPUT_DIR/subdomains/403_hosts.txt")  ← bypass candidates"
    [[ -f "$OUTPUT_DIR/subdomains/401_hosts.txt" ]]     && echo "  401 Unauthorized:    $(wc -l < "$OUTPUT_DIR/subdomains/401_hosts.txt")  ← auth walls"
    [[ -f "$OUTPUT_DIR/subdomains/redirect_hosts.txt" ]]&& echo "  Redirects:           $(wc -l < "$OUTPUT_DIR/subdomains/redirect_hosts.txt")"
    echo ""
    echo "──────────────────── URLS ──────────────────────────────"
    [[ -f "$OUTPUT_DIR/urls/raw_urls.txt" ]]            && echo "  Raw harvested:       $(wc -l < "$OUTPUT_DIR/urls/raw_urls.txt")"
    [[ -f "$OUTPUT_DIR/urls/clean_urls.txt" ]]          && echo "  After cleaning:      $(wc -l < "$OUTPUT_DIR/urls/clean_urls.txt")"
    [[ -f "$OUTPUT_DIR/urls/api_urls.txt" ]]            && echo "  API endpoints:       $(wc -l < "$OUTPUT_DIR/urls/api_urls.txt")"
    [[ -f "$OUTPUT_DIR/urls/js_urls.txt" ]]             && echo "  JS files:            $(wc -l < "$OUTPUT_DIR/urls/js_urls.txt")"
    [[ -f "$OUTPUT_DIR/urls/redirect_params.txt" ]]     && echo "  Redirect params:     $(wc -l < "$OUTPUT_DIR/urls/redirect_params.txt")"
    [[ -f "$OUTPUT_DIR/urls/idor_params.txt" ]]         && echo "  IDOR candidates:     $(wc -l < "$OUTPUT_DIR/urls/idor_params.txt")  ← test with your OAuth knowledge"
    echo ""
    echo "──────────────────── JS ANALYSIS ───────────────────────"
    [[ -f "$OUTPUT_DIR/js/grep_keywords.txt" ]]         && echo "  grep keywords:       $(wc -l < "$OUTPUT_DIR/js/grep_keywords.txt")"
    [[ -f "$OUTPUT_DIR/js/endpoints.txt" ]]             && echo "  Endpoints found:     $(wc -l < "$OUTPUT_DIR/js/endpoints.txt")"
    [[ -d "$OUTPUT_DIR/js/gf" ]]                        && echo "  gf pattern hits:     $(cat "$OUTPUT_DIR/js/gf/"*.txt 2>/dev/null | sort -u | wc -l)"
    [[ -f "$OUTPUT_DIR/js/trufflehog_results.json" ]]   && echo "  trufflehog secrets:  $TH_HITS  ← HIGH PRIORITY if > 0"
    echo ""
    echo "──────────────────── PRIORITY ACTIONS ─────────────────"
    echo ""

    # Dynamic priority list based on what was found
    priority=1

    if [[ -f "$OUTPUT_DIR/js/trufflehog_results.json" ]] && [[ "$TH_HITS" -gt 0 ]]; then
      echo "  [$priority] CRITICAL — $TH_HITS secrets in $OUTPUT_DIR/js/trufflehog_results.json"
      ((priority++))
    fi

    [[ -s "$OUTPUT_DIR/js/grep_keywords.txt" ]] && \
      echo "  [$priority] Review JS keywords: $OUTPUT_DIR/js/grep_keywords.txt" && ((priority++))

    [[ -s "$OUTPUT_DIR/subdomains/403_hosts.txt" ]] && \
      echo "  [$priority] Try 403 bypass on:  $OUTPUT_DIR/subdomains/403_hosts.txt" && ((priority++))

    [[ -s "$OUTPUT_DIR/urls/api_urls.txt" ]] && \
      echo "  [$priority] Test API endpoints: $OUTPUT_DIR/urls/api_urls.txt" && ((priority++))

    [[ -s "$OUTPUT_DIR/urls/idor_params.txt" ]] && \
      echo "  [$priority] IDOR candidates:    $OUTPUT_DIR/urls/idor_params.txt" && ((priority++))

    [[ -s "$OUTPUT_DIR/urls/redirect_params.txt" ]] && \
      echo "  [$priority] Open redirect test: $OUTPUT_DIR/urls/redirect_params.txt" && ((priority++))

    [[ -s "$OUTPUT_DIR/js/endpoints.txt" ]] && \
      echo "  [$priority] Hidden endpoints:   $OUTPUT_DIR/js/endpoints.txt" && ((priority++))

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
  # js mode needs alive.txt to exist for gau
  [[ ! -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && {
    warn "No alive.txt found — running passive + active first..."
    passive_subs
    probe_alive
  }
  harvest_urls
  analyze_js
  generate_report
}

run_fuzz() {
  [[ ! -f "$OUTPUT_DIR/subdomains/alive.txt" ]] && {
    warn "No alive.txt found — running passive + active first..."
    passive_subs
    probe_alive
  }
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
  info "Summary report: ${BOLD}$OUTPUT_DIR/reports/summary.txt${RESET}"
}

main
