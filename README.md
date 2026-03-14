# recon_Tool
A modular, rate-limited bug bounty recon framework with 5 scanning modes
<div align="center">

```
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
```

**Professional Bug Bounty Recon Framework**

![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![BugBounty](https://img.shields.io/badge/Use%20Case-Bug%20Bounty-red?style=flat-square)

*A modular, rate-limited recon framework built for bug bounty hunters who care about methodology.*

</div>

---

## What is Phantom Recon?

Phantom Recon is a structured, multi-mode bash recon framework designed for bug bounty hunters. It chains together industry-standard tools into a controlled, repeatable pipeline — with built-in rate limiting and delay controls so you don't get banned from your targets.

It is **not** a scanner. It is a **recon framework** that maps attack surface intelligently, then hands you organized, categorized output to work from manually.

---

## Features

- **5 distinct modes** — from fully passive to complete pipeline
- **Rate limiting on every tool** — configurable threads, req/s, and delays
- **Automatic output categorization** — API endpoints, redirect params, JS files, 403/401 hosts all separated
- **JavaScript secrets analysis** — scans downloaded JS for API keys, tokens, hardcoded credentials
- **Auto-generated summary report** with actionable next steps
- **Timestamped output directories** — never overwrite previous recon runs
- Clean, color-coded terminal output

---

## Modes

| Mode | Description | Direct Contact | Use When |
|------|-------------|---------------|----------|
| `passive` | Subfinder + Amass passive enumeration only | ❌ None | Always safe to start here |
| `active` | Passive + controlled httpx probing | ✅ Low | Program allows probing |
| `full` | Complete pipeline — subs, alive, URLs, JS, fuzzing | ✅ Medium | Full recon run on a target |
| `js` | JavaScript harvesting + secrets extraction only | ✅ Low | Targeted JS analysis |
| `fuzz` | Directory & parameter fuzzing on alive hosts | ✅ Medium | Finding hidden endpoints |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/phantom-recon.git
cd phantom-recon
chmod +x recon.sh
```

### 2. Install dependencies

**On Arch Linux (recommended):**
```bash
yay -S subfinder amass httpx-toolkit gau ffuf seclists
```

**On Debian/Ubuntu:**
```bash
# Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest

# Amass
go install github.com/owasp-amass/amass/v4/...@master

# SecLists
sudo apt install seclists
```

> Make sure your Go binary path is in `$PATH`:
> ```bash
> export PATH=$PATH:$(go env GOPATH)/bin
> ```

---

## Usage

```bash
./recon.sh -d <domain> -m <mode> [options]
```

### Options

| Flag | Long form | Default | Description |
|------|-----------|---------|-------------|
| `-d` | `--domain` | required | Target domain |
| `-m` | `--mode` | required | Recon mode |
| `-t` | `--threads` | `5` | Thread count |
| `-r` | `--rate` | `10` | Max requests per second |
| `--delay` | `--delay` | `1` | Seconds between module runs |
| `-w` | `--wordlist` | seclists common.txt | Custom wordlist path |
| `-h` | `--help` | — | Show help |

### Examples

```bash
# Start safe — passive only
./recon.sh -d target.com -m passive

# Active probing with custom rate
./recon.sh -d target.com -m active -t 5 -r 15

# Full pipeline, gentle settings
./recon.sh -d target.com -m full -t 3 -r 10 --delay 2

# JS analysis only
./recon.sh -d target.com -m js

# Fuzzing with custom wordlist
./recon.sh -d target.com -m fuzz -w /path/to/wordlist.txt -r 20
```

---

## Output Structure

Every run creates a timestamped directory `phantom_<target>_<timestamp>/` with the following structure:

```
phantom_target.com_20250101_120000/
├── subdomains/
│   ├── subfinder.txt         # Raw subfinder results
│   ├── amass.txt             # Raw amass results
│   ├── all_subs.txt          # Merged & deduplicated
│   ├── alive.txt             # Live hosts with status codes & tech stack
│   ├── 403_hosts.txt         # 403 hosts — potential bypass targets
│   └── 401_hosts.txt         # 401 hosts — auth-protected endpoints
├── urls/
│   ├── all_urls.txt          # All harvested URLs
│   ├── js_urls.txt           # JavaScript file URLs
│   ├── json_urls.txt         # JSON endpoint URLs
│   ├── api_urls.txt          # API path URLs
│   ├── dynamic_urls.txt      # PHP, ASP, JSP pages
│   └── redirect_params.txt   # URLs with redirect parameters
├── js/
│   ├── files/                # Downloaded JS files
│   ├── endpoints.txt         # Extracted endpoints from JS
│   ├── sensitive_keywords.txt # API keys, tokens, secrets found
│   └── potential_tokens.txt  # Long strings that may be credentials
├── fuzzing/
│   └── <host>.json           # ffuf results per host
└── reports/
    └── summary.txt           # Full summary with next steps
```

---

## Recon Pipeline

```
Target Domain
      │
      ▼
┌─────────────────┐
│ Passive Enum    │  subfinder + amass --passive
│ (zero contact)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Probe Alive     │  httpx (rate-limited)
│ hosts           │  → separates 200 / 401 / 403
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ URL Harvesting  │  gau (wayback + otx + commoncrawl)
│ (historical)    │  → categorizes by type
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ JS Analysis     │  download + grep for secrets
│                 │  endpoints, tokens, API keys
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Fuzzing         │  ffuf (rate-limited)
│                 │  → hidden dirs & endpoints
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Summary Report  │  categorized findings
│                 │  + next steps
└─────────────────┘
```

---

## Rate Limiting — Why It Matters

Phantom Recon enforces rate limiting at every stage. This is not optional — it protects you from:

- Getting your IP banned from the target
- Violating program scope rules
- Triggering WAF/IDS alerts that invalidate your findings
- Potential legal issues with aggressive scanning

**Recommended settings by target sensitivity:**

| Target Type | Threads | Rate | Delay |
|-------------|---------|------|-------|
| Large program (Google, Meta) | 3 | 5 | 3 |
| Medium program | 5 | 10 | 2 |
| Small/new program | 5 | 15 | 1 |

---

## Important — Read Before Hunting

> **Always read the program's scope and rules before running any recon.**

- Some programs **explicitly ban automated tools** — respect this
- `passive` mode is always safe — zero direct contact with target
- `active`, `full`, and `fuzz` modes make direct HTTP requests — check the policy first
- Never use this tool against targets outside of an authorized bug bounty program
- Never use a VPN to bypass a ban you already received

This tool is built for **ethical, authorized bug bounty hunting only.**

---

## What to Do With the Output

After a recon run, prioritize in this order:

1. **`403_hosts.txt`** — Try 403 bypass techniques (`X-Forwarded-For`, path manipulation)
2. **`api_urls.txt`** — Test each endpoint for broken access control and auth issues
3. **`js/sensitive_keywords.txt`** — Manually verify any API keys or tokens found
4. **`redirect_params.txt`** — Test for open redirect vulnerabilities
5. **`401_hosts.txt`** — Investigate what's behind the auth wall
6. **`js/endpoints.txt`** — Hidden endpoints extracted from JS — test each one

---

## Dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration 
| [amass](https://github.com/owasp-amass/amass) | Advanced subdomain enumeration 
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing & tech detection 
| [gau](https://github.com/lc/gau) | Historical URL harvesting 
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer 
| [SecLists](https://github.com/danielmiessler/SecLists) 

---

## Contributing

Pull requests are welcome. If you have a module idea (e.g., parameter mining, nuclei integration, screenshots), open an issue first to discuss it.

---

## License

MIT License — use freely, hunt responsibly.

---

<div align="center">
Built for the bug bounty community. Hunt smart, not loud.
</div>
