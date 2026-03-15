---
layout: post
title: "The Operator's Pentest Playbook"
date: 2026-03-15
categories: [security]
excerpt: "> Recon = learn. You are building a mental map before touching anything. The goal is information, not interaction."
slug: the-operators-pentest-playbook
author: Decker
---

# The Operator's Pentest Playbook
## Chapter 3: Phase 2: Reconnaissance

## Phase 2: Reconnaissance

**At this stage:**
- ❌ No payloads
- ❌ No brute force
- ❌ No login attempts
- ❌ No active scanning
- ✅ Passive observation only

The best pentesters spend more time here than anywhere else. The more you know before you touch the target, the more targeted and effective your later phases will be.

### 2.1 DNS Enumeration

DNS (Domain Name System) is the internet's phone book. It converts `example.com` into an IP address your computer can connect to. But DNS also stores a lot of other information — and organizations often leak infrastructure details through it.

**Why DNS matters for pentesting:**
- Reveals which IP addresses belong to this organization
- Shows what third-party services they use
- Exposes subdomains (dev, staging, admin, api) that might be softer targets
- Can reveal mail server setup (useful for phishing scope assessment)
- Sometimes reveals internal hostnames

**The commands:**

```bash
# Quick overview — all record types at once
host -t any "$TARGET" | tee raw/dns_host.txt

# Detailed queries by record type
dig "$TARGET" A     | tee -a raw/dns_all.txt   # IPv4 address
dig "$TARGET" AAAA  | tee -a raw/dns_all.txt   # IPv6 address
dig "$TARGET" MX    | tee -a raw/dns_all.txt   # Mail servers
dig "$TARGET" NS    | tee -a raw/dns_all.txt   # Nameservers
dig "$TARGET" TXT   | tee -a raw/dns_all.txt   # Text records (SPF, DKIM, verifications)
dig "$TARGET" CNAME | tee -a raw/dns_all.txt   # Aliases
dig "$TARGET" SOA   | tee -a raw/dns_all.txt   # Zone authority

log "DNS enumeration complete"
```

**Reading the output — what each record tells you:**

```bash
# A record — the main IP address
# example.com. IN A 93.184.216.34
# → Single IP = probably not load balanced (smaller setup)
# → Multiple IPs = load balanced (larger infrastructure)

# MX records — mail servers
# example.com. IN MX 10 aspmx.l.google.com.
# → Google mail servers = they use Google Workspace for email
# → mail.example.com = self-hosted mail (older, potentially vulnerable)

# NS records — nameservers  
# example.com. IN NS ns1.cloudflare.com.
# → Cloudflare = WAF likely present on web app, may block scans
# → ns1.example.com = self-hosted DNS (check for zone transfer)

# TXT records — contain policy and verification info
# v=spf1 include:sendgrid.net include:mailchimp.com -all
# → Uses SendGrid and Mailchimp for email → external SaaS tools
# → google-site-verification=XXX → Google Workspace
# → MS=ms12345678 → Microsoft 365
```

**Check for zone transfer (rare but high value):**

A zone transfer gives you the complete list of all DNS records — essentially a map of the entire infrastructure. Most DNS servers are configured to reject this, but occasionally they're not.

```bash
# Get the nameserver first
NS=$(dig NS "$TARGET" +short | head -1)
echo "Nameserver: $NS"

# Attempt zone transfer
dig axfr "$TARGET" @"$NS" | tee raw/dns_zonetransfer.txt

# If it works, you'll see ALL DNS records
# If it fails, you'll see "Transfer failed"
```

**What to look for in TXT records:**

```bash
# Parse TXT records for interesting content
dig "$TARGET" TXT +short | tee raw/dns_txt.txt

# Check for third-party services
grep -i "spf\|sendgrid\|mailchimp\|salesforce\|zendesk\|atlassian\|github\|google\|microsoft\|aws\|verify" raw/dns_txt.txt
```

**Follow-up actions based on DNS findings:**

| Finding | What It Means | What To Do Next |
|---------|---------------|-----------------|
| Single A record | Small/simple infrastructure | Scan that IP directly |
| Multiple A records | Load balanced | Test each IP — configs may differ |
| Cloudflare NS | WAF in front of server | Try to find real origin IP (Shodan, old DNS records) |
| Google MX | Google Workspace email | Note for scope (usually out of scope) |
| Self-hosted MX | Own mail server | Add to scope discussion, check for open relay |
| Zone transfer works | DNS misconfiguration | Critical finding — document immediately |
| Old/forgotten NS records | Legacy infrastructure | Those old IPs may still be live and unpatched |

**Record findings in memory/recon.md:**

```markdown
## DNS Findings — example.com — 2026-02-27

### Records
- A: 93.184.216.34 (single IP — not load balanced)
- AAAA: none (no IPv6)
- MX: aspmx.l.google.com (Google Workspace)
- NS: ns1.cloudflare.com, ns2.cloudflare.com (Cloudflare)
- TXT: v=spf1 include:sendgrid.net → uses SendGrid
- TXT: MS=ms62451234 → Microsoft 365 tenant
- Zone transfer: REFUSED

### What This Tells Me
- Behind Cloudflare CDN/WAF — real IP may be hidden
- Uses Google for email, Microsoft 365 for auth (interesting — mixed vendors)
- SendGrid = email marketing — potential phishing vector (out of scope)

### Hypotheses
- Cloudflare may WAF-block some scans — try to find origin IP
- Real server IP may be exposed via historical DNS (check SecurityTrails)
```

### 2.2 Finding the Real IP Behind a CDN

If the target uses Cloudflare or another CDN, the IP you get from DNS is the CDN's IP, not the real server. The real server may have fewer protections. Finding it is a legitimate part of reconnaissance.

```bash
# Check historical DNS records (web-based tools)
# https://securitytrails.com/domain/example.com
# https://viewdns.info/iphistory/?domain=example.com
# https://www.shodan.io/search?query=ssl.cert.subject.cn:example.com

# Check if the real IP is exposed via SSL certificate
curl -sk "https://$TARGET" -o /dev/null -w "%{remote_ip}\n"

# Sometimes the real IP is in email headers — if you can receive email from them:
# Look at the Received: headers in any email from @example.com

# Try connecting to origin directly (common Cloudflare bypass test)
curl -sk "https://$TARGET_IP" -H "Host: $TARGET" | head -20
```

### 2.3 WHOIS & Registration Data

WHOIS gives you organizational context — who owns this, how big are they, what else do they own.

```bash
# Domain WHOIS
whois "$TARGET" | tee raw/whois_domain.txt

# IP WHOIS (who owns the IP block)
whois "$TARGET_IP" | tee raw/whois_ip.txt

# Get ASN (Autonomous System Number — identifies the organization's network)
curl -s "https://ipinfo.io/$TARGET_IP" | tee raw/ipinfo.json
```

**What to extract from WHOIS:**

```bash
# Quick parse of useful fields
echo "=== Domain Registration ===" 
whois "$TARGET" | grep -iE "(registrar|created|updated|expires|name server|registrant|email|organization|country)"
```

**What each field tells you:**

- **Registrar**: Godaddy/Namecheap = consumer-grade (likely not sophisticated). Corporate registrar = enterprise.
- **Created date**: Domain registered in 2004 = old organization with legacy systems. Registered last year = newer, possibly cloud-native.
- **Registrant email**: If not privacy-protected, this is an OSINT pivot. Search for this email in leaked credential databases.
- **Organization**: Tells you the legal name — search LinkedIn, Crunchbase, etc.
- **Name servers**: Self-hosted = they manage DNS (check zone transfer). Third-party = outsourced.

**IP WHOIS useful info:**

```bash
# Parse IP ownership
whois "$TARGET_IP" | grep -iE "(netname|orgname|country|abuse|cidr|netrange)"

# What to look for:
# CIDR/NetRange: shows the full IP range they own — scan the range if in scope
# OrgName: the actual company/cloud provider owning the IP
# Abuse contact: useful to note (not for your engagement, just for context)
```

### 2.4 Subdomain Enumeration

Subdomains are where organizations leave their most vulnerable targets. Development environments have debug features on. Staging servers have test accounts. Old apps haven't been updated in years. Admin panels exist without being advertised.

**Method 1: Passive enumeration via Certificate Transparency logs**

When a website gets an SSL certificate, it's logged publicly. This means every subdomain that has ever had a certificate is publicly searchable — without touching the target at all.

```bash
# Query crt.sh — completely passive, no target contact
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | tee raw/subfinder/crtsh.txt

echo "[+] Found $(wc -l < raw/subfinder/crtsh.txt) subdomains via crt.sh"
log "Certificate transparency enumeration complete"
```

**Method 2: subfinder (aggregates multiple passive sources)**

```bash
subfinder -d "$TARGET" -silent -o raw/subfinder/subfinder.txt
echo "[+] Found $(wc -l < raw/subfinder/subfinder.txt) subdomains via subfinder"
log "Subfinder enumeration complete"
```

**Method 3: Combine and deduplicate all sources**

```bash
cat raw/subfinder/crtsh.txt raw/subfinder/subfinder.txt \
  | sort -u \
  | grep "\.$TARGET$\|^$TARGET$" \
  > raw/subfinder/all_subdomains.txt

echo "[+] Total unique subdomains: $(wc -l < raw/subfinder/all_subdomains.txt)"
```

**Method 4: Check which ones are actually alive**

Finding a subdomain in a database doesn't mean it's still running. Probe each one:

```bash
# Install httpx (fast HTTP prober)
# See Appendix A for installation
httpx -l raw/subfinder/all_subdomains.txt \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -o raw/subfinder/alive_subdomains.txt

echo "[+] Live subdomains: $(wc -l < raw/subfinder/alive_subdomains.txt)"
log "Subdomain liveness check complete"
```

**Method 5: DNS brute force (active — check scope)**

This generates DNS requests — it's active, not passive. Make sure it's allowed.

```bash
# Using subfinder's brute mode
subfinder -d "$TARGET" -active -o raw/subfinder/brute.txt

# Or with ffuf against a wordlist
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u "https://FUZZ.$TARGET" \
  -mc 200,301,302,401,403 \
  -o raw/subfinder/ffuf_subdomains.json \
  -of json 2>/dev/null
```

**Categorize what you find:**

```markdown
## Subdomain Analysis

### High Priority (investigate first)
- admin.example.com    [200 OK] "Admin Panel"       → admin interface
- portal.example.com   [200 OK] "Client Portal"     → authenticated app
- api.example.com      [200 OK] "{"version":"2.1"}  → REST API

### Dev/Staging (likely weaker controls)
- dev.example.com      [200 OK] "Development Site"  → dev environment
- staging.example.com  [302]    → redirects to staging app
- test.example.com     [403]    → exists, blocked

### Legacy/Forgotten
- old.example.com      [200 OK] Apache 2.2          → very old web server!
- legacy.example.com   [200 OK] running Joomla 3.2  → outdated CMS

### Third-Party/CNAME
- mail.example.com     → CNAME to Google
- cdn.example.com      → CNAME to CloudFront
- support.example.com  → CNAME to Zendesk
```

### 2.5 OSINT — Open Source Intelligence

OSINT is gathering information from public sources. This gives you context about the organization, its people, and sometimes directly useful technical information.

**Google Dorking — using Google to find things Google indexed that shouldn't be public:**

```bash
# These are search queries to run in Google, not the terminal
# Replace "example.com" with your target

# Find login pages indexed by Google
site:example.com inurl:login
site:example.com inurl:admin
site:example.com inurl:portal

# Find exposed files
site:example.com filetype:pdf
site:example.com filetype:xlsx
site:example.com filetype:sql
site:example.com filetype:log
site:example.com filetype:env
site:example.com filetype:bak

# Find configuration files
site:example.com intitle:"index of"        # directory listings
site:example.com "DB_PASSWORD"             # config file contents indexed
site:example.com "api_key"                 # API keys in public pages
site:example.com "BEGIN RSA PRIVATE KEY"   # private keys (rare but happens)

# Find subdomains Google knows about
site:*.example.com -site:www.example.com

# Find error pages that leak technology info
site:example.com "stack trace"
site:example.com "fatal error"
site:example.com "mysql_fetch_array"
```

**Shodan — search engine for internet-connected devices:**

Shodan crawls the internet and indexes what it finds running on every IP. You can search for your target without sending a single packet to them.

```bash
# Web searches at shodan.io (no terminal needed for basic use):
# hostname:example.com
# ssl.cert.subject.cn:example.com
# org:"Example Company Name"

# CLI (requires API key — free tier available):
sudo apt install -y python3-shodan
shodan init YOUR_API_KEY
shodan host "$TARGET_IP"
shodan search "hostname:$TARGET" --fields ip_str,port,org,hostnames
```

**What Shodan reveals:**
- Open ports (including non-standard ones you might miss in a scan)
- Software versions
- Historical data (what was running in the past)
- SSL certificate info (reveals other domains on the same cert)
- Geographic location of servers

**theHarvester — email, name, and subdomain harvesting:**

```bash
theHarvester -d "$TARGET" -b all -f raw/theharvester.html

# Specific sources:
theHarvester -d "$TARGET" -b google,bing,linkedin,github -l 200
```

**Finding credentials in paste sites and breach databases:**

```bash
# These are web services — use them manually:
# https://haveibeenpwned.com — check if email addresses have been in breaches
# https://dehashed.com — search leaked credential databases (paid)
# https://intelx.io — search paste sites, dark web, breaches

# Look for target employees on LinkedIn, then check their emails in HIBP
# Breached credentials can sometimes still work (password reuse is extremely common)
```

**GitHub & Code Repository Search:**

Organizations accidentally commit secrets (API keys, passwords, credentials) to public repositories. This happens constantly and is one of the most common real-world findings.

```bash
# Web searches on github.com:
# org:ExampleCompany password
# org:ExampleCompany api_key
# org:ExampleCompany secret
# org:ExampleCompany "example.com" password
# "example.com" DB_PASSWORD

# Use trufflehog to scan a GitHub org for secrets:
trufflehog github --org=ExampleCompany --only-verified

# Or scan a specific repo:
trufflehog git https://github.com/ExampleCompany/repo-name
```

**Web Archive — what the site used to look like:**

```bash
# Visit the Wayback Machine to see historical versions:
# https://web.archive.org/web/*/example.com

# Useful for:
# Finding old endpoints that still exist but aren't linked
# Seeing what technologies were used previously
# Finding admin pages that were removed from navigation but not deleted
```

### 2.6 Passive HTTP Fingerprinting

Before actively scanning, you can learn a lot from the raw HTTP response the target sends when you visit it normally.

```bash
# Check HTTP headers (what does the server announce about itself?)
curl -sI "https://$TARGET" | tee raw/headers.txt

# Check both HTTP and HTTPS
curl -sI "http://$TARGET" | tee raw/headers_http.txt
curl -sI "https://$TARGET" | tee raw/headers_https.txt

# Verbose — see the full request/response exchange
curl -sv "https://$TARGET" -o /dev/null 2>&1 | tee raw/curl_verbose.txt
```

**Reading HTTP headers:**

```
HTTP/2 200
server: Apache/2.4.49 (Ubuntu)          ← Server software and version (should be hidden)
x-powered-by: PHP/7.4.3                 ← Backend language (should be hidden)
set-cookie: PHPSESSID=abc123            ← Session cookie name (reveals PHP backend)
x-generator: Drupal 9                   ← CMS (reveals attack surface)
x-frame-options: DENY                   ← Security header present (good)
content-security-policy: ...            ← CSP header (check quality)
```

**Security headers check:**

```bash
# Check which security headers are present/missing
echo "=== Security Headers Check ==="
for header in "strict-transport-security" "content-security-policy" "x-frame-options" \
              "x-content-type-options" "x-xss-protection" "permissions-policy" \
              "referrer-policy" "cross-origin-opener-policy"; do
  result=$(curl -sI "https://$TARGET" | grep -i "$header")
  if [ -n "$result" ]; then
    echo "✅ PRESENT: $header"
    echo "   $result"
  else
    echo "❌ MISSING: $header"
  fi
done
```

**Each missing header is potentially a reportable finding:**

| Missing Header | Risk | Severity |
|----------------|------|----------|
| Strict-Transport-Security | HTTP downgrade attacks possible | Medium |
| Content-Security-Policy | XSS impact increased | Medium |
| X-Frame-Options | Clickjacking attacks possible | Low-Medium |
| X-Content-Type-Options | MIME sniffing attacks possible | Low |
| Referrer-Policy | Information leakage to third parties | Low |

**Cookies analysis:**

```bash
# Check cookies for security flags
curl -sI "https://$TARGET" | grep -i "set-cookie"

# What to look for in cookies:
# HttpOnly — prevents JavaScript from reading the cookie (XSS protection)
# Secure — cookie only sent over HTTPS
# SameSite — CSRF protection
# Domain — scope of the cookie

# Example of a GOOD session cookie:
# Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/

# Example of a BAD session cookie (all flags missing = multiple vulnerabilities):
# Set-Cookie: session=abc123
```

---
