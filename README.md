# TrustScan — Product Architecture: Engines & Lifecycle

A standalone Digital Trust Intelligence Platform designed to integrate with TrustLayer.

---

## Product Identity

| Property | Value |
|----------|-------|
| **Tagline** | Map and protect your digital business. |
| **Target** | Kenyan SMEs, SACCOs, churches, schools, hospitals — any organization with a domain and no security team |
| **Price Position** | Affordable per-scan or monthly subscription — not enterprise-priced like SecurityScorecard or Wiz |

---

## Core Principle

TrustScan is a **read-only intelligence platform**. It never touches a customer's infrastructure — no login attempts, no port scanning beyond passive lookups, no brute force. It queries information a business has already made public, scores it, and explains what the score means.

**The question the whole product answers:** *What can the internet already see about this domain?*

The raw data isn't the product — anyone can query DNS. The product is **interpretation** (translating technical findings into business risk), **scoring** (weighting findings for the Kenyan context), and **action** (telling the owner exactly what to fix and why).

---

## The Five Engines

### 1. Discovery Engine — find everything that exists

Takes one input, a domain, and expands it into every discoverable asset before any analysis begins.

- **DNS resolution** — IP addresses, name servers, MX records
- **Certificate Transparency** — every subdomain that has ever been issued an SSL certificate
- **Passive DNS history** — subdomains seen by internet crawlers over time
- **WHOIS & registry** — registration details, expiry, privacy status

**Output:** a **Discovery Map** — the full inventory of assets found. Discovery is non-destructive and passive throughout — no brute force, no login attempts.

---

### 2. Reconnaissance Engine — interrogate each asset

For every asset in the Discovery Map, this engine asks specific security questions, each mapped to a real-world risk.

| Module | Question it answers |
|--------|---------------------|
| DNS Inspector | Is DNS configured securely? (SPF, DKIM, DMARC, DNSSEC, zone transfers) |
| SSL/TLS Inspector | Is encryption properly implemented? (validity, expiry, cipher strength) |
| Email Security Inspector | Can attackers spoof emails from this domain? |
| Web Security Inspector | Are security headers present? (HSTS, CSP, X-Frame-Options) |
| Technology Profiler | What software is running? (headers, HTML source, favicon hashes) |
| Exposure Detector | Are sensitive services visible? (admin panels, databases, open ports) |
| Breach Intelligence | Have credentials tied to this domain been leaked? |
| Reputation Monitor | Is this domain trusted? (blacklists, malware feeds, Safe Browsing) |

---

### 3. Correlation Engine — connect findings into patterns

Individual findings are noise. This engine finds the patterns across them — this is where the product becomes intelligent rather than a data dump.

| Pattern | What it means | Risk |
|---------|---------------|------|
| Shadow IT | A subdomain like `pay.hospital.co.ke` exists but isn't in the asset register | Critical |
| Certificate mismatch | A subdomain serves a certificate for an unrelated service — misconfiguration or hijack | Critical |
| Email spoofing chain | SPF allows all, DMARC has no enforcement, DKIM missing | High |
| Breach cascade | Multiple employee emails leaked, some sharing password patterns | High |
| Exposed admin, no MFA | An admin panel is public with no second factor and outdated software | Critical |
| Domain expiry risk | Domain expires soon with no auto-renew, business-critical email tied to it | High |

---

### 4. Scoring Engine — the moat

Converts findings and correlations into a single, explainable Trust Score.

| Dimension | Weight | What it measures |
|-----------|--------|------------------|
| Identity Integrity | 20% | Can the organization prove domain ownership? Is WHOIS accurate? |
| Email Security | 20% | SPF / DKIM / DMARC strength — can this domain be impersonated in email? |
| Infrastructure Hygiene | 15% | SSL validity, DNSSEC, certificate management |
| Exposure Surface | 15% | Discoverable assets, sensitive subdomains, open services |
| Breach History | 15% | Credential leaks, past compromises |
| Reputation & Trust | 15% | Blacklist status, domain age, spam scores |

Scoring is **rule-based, not machine-learned**, for v1: transparent, auditable, and fast to tune for the Kenyan market. Every score has to be explainable to a business owner who has never heard of DMARC.

| Score Range | Label | Meaning |
|-------------|-------|---------|
| 90–100 | Excellent | Strong posture, low risk of impersonation or compromise |
| 70–89 | Good | Solid foundation, minor issues to address |
| 50–69 | Fair | Visible weaknesses, action recommended |
| 30–49 | Poor | Significant exposure, high risk of incident |
| 0–29 | Critical | Immediate action required |

---

### 5. Intelligence Engine — what makes it irreplaceable

Analyzes trends across all scanned domains and turns a raw score into strategy.

- **Peer benchmarking** — "Your score is 72; the average for Kenyan hospitals is 58"
- **Trend analysis** — "Your score dropped 15 points after a new, unsecured subdomain appeared"
- **Threat context** — "A phishing campaign is currently targeting .co.ke healthcare domains"
- **Regulatory mapping** — Whether the current configuration meets Kenya Data Protection Act requirements

---

## The Full Lifecycle of a Scan

| Phase | Engine | What happens | Duration |
|-------|--------|--------------|----------|
| **1. Initiation** | — | User, schedule, API call, or bulk import triggers a scan; a Scan Job is created as PENDING | Instant |
| **2. Discovery** | Discovery Engine | DNS, certificate logs, passive DNS, and WHOIS are queried; Discovery Map is built | 10–30 sec |
| **3. Reconnaissance** | Reconnaissance Engine | Every asset is interrogated in parallel; findings aggregated | 30–90 sec |
| **4. Correlation** | Correlation Engine | Findings are pattern-matched into systemic risks | 5–10 sec |
| **5. Scoring** | Scoring Engine | Weighted rules applied; overall and per-dimension scores calculated | 2–5 sec |
| **6. Intelligence** | Intelligence Engine | Compared to history and peers; narrative brief generated | 2–5 sec |
| **7. Delivery** | — | Executive summary, technical report, and API response compiled and sent | Instant |
| **8. Monitoring** | — | Domain enters portfolio; rescans scheduled; alerts fire on score drops or new critical findings | Ongoing |

**Failure handling** is built in at every phase: a domain that won't resolve fails cleanly as `DOMAIN_NOT_FOUND`; an unreachable external API marks findings `INCOMPLETE` and the scan continues rather than blocking.

---

## Data Architecture — Core Entities

| Entity | Purpose |
|--------|---------|
| **Organization** | The customer. Can own multiple domains. |
| **Domain** | The scan target, linked to an organization. |
| **Scan Job** | One scan execution — tracks status, timing, scoring version. |
| **Asset** | A discovered resource: subdomain, IP, mail server. |
| **Finding** | A single security observation, linked to an asset. |
| **Correlation** | A pattern linking multiple findings. |
| **Trust Score** | The calculated scores for a scan job. |
| **Intelligence Brief** | Narrative insight generated from the score and trends. |
| **Trust Report** | The unified deliverable — score, findings, correlations, intelligence. |

---

## Integration With TrustLayer

TrustScan runs standalone — a business can sign up, add domains, and view reports with no dependency on TrustLayer. The integration is optional, and one-directional in trust: TrustLayer asks, TrustScan answers, and TrustLayer decides.

Before an agreement moves from `CREATED` to `CONFIRMED`, TrustLayer's Rule Engine can call TrustScan for the counterparty's domain score:

- **Score ≥ 70** → proceed to `CONFIRMED`
- **Score 50–69** → proceed, but flagged for hold
- **Score < 50** → `REJECTED`, reason: *"digital identity verification failed"*

**Decoupling principle:** TrustLayer never knows how TrustScan calculates a score — only the score and the recommendation. If TrustScan is unreachable, TrustLayer defaults to manual review rather than failing.

---

## Monetization

| Tier | Price (KES/month) | Included |
|------|-------------------|----------|
| Free | 0 | 1 domain, 1 scan/month, basic report |
| Business | ~2,500 | 3 domains, weekly scans, alerts, PDF reports |
| Pro | ~7,500 | 10 domains, daily scans, API access, white-label |
| Enterprise | Custom | Unlimited domains, custom rules, SLA |

The sell is **reputation protection, not cybersecurity** — most Kenyan SMEs will never pay for SecurityScorecard, but will pay to avoid a spoofed domain or a hacked email.

---

## Roadmap

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| MVP | Weeks 1–4 | DNS + certificate + SSL scanners, basic Trust Score, web report |
| v1.0 | Weeks 5–8 | Breach checker, tech fingerprinting, subdomain discovery, PDF reports |
| v1.5 | Months 3–4 | Alerting, scheduling, multi-domain portfolios, M-Pesa billing |
| v2.0 | Months 5–6 | API launch, white-label for resellers, TrustLayer integration docs |
| Platform | Year 2 | Trust Intelligence module inside TrustLayer, AI-assisted recommendations |

---

## What Makes It Hard to Copy

- **Kenyan context rules** — knowing that a missing DMARC record on a `.co.ke` domain is common today but dangerous, and weighting it accordingly
- **The integration with TrustLayer** — once a score feeds real transaction decisions, the data is worth more than the scanner alone
- **The scoring algorithm itself** — weights tuned over time against real fraud patterns observed through TrustLayer

---

## Build Order

**Discovery and Reconnaissance are the foundation** — build those first.  
The **Scoring Engine is the moat**.  
The **Intelligence Engine is what makes the product irreplaceable** once enough domains have been scanned to benchmark against.

---

## Authorization Flow

1. User adds domain (e.g., `company.co.ke`)
2. System generates verification token
3. User proves ownership via:
   - **DNS TXT Record** (primary) — Add `trustscan-verify=<token>`
   - **HTML File** — Upload `trustscan_<token>.html` to web root
   - **Meta Tag** — Add `<meta name="trustscan-verification" content="<token>">`
   - **Email** — Click link sent to `admin@`/`webmaster@`/`postmaster@`
4. Domain marked `AUTHORIZED` — scanning permitted
5. User can revoke authorization anytime

---

## TrustLayer API Integration

```bash
# Get trust score for counterparty
GET /api/v1/public/trustscan/score/example.co.ke

# Response
{
  "domain": "example.co.ke",
  "trust_score": {
    "overall": 86,
    "dimensions": {
      "email_security": 90,
      "infrastructure_hygiene": 85,
      "exposure_surface": 80,
      "breach_history": 95,
      "reputation": 78,
      "identity_integrity": 88
    }
  },
  "recommendation": "PROCEED",
  "critical_risks": 0
}
```

---

## Global Support

Works with any TLD (`.com`, `.org`, `.co.ke`, `.io`, etc.) and email addresses (e.g., `joelkaunda15@gmail.com` for email identity scanning).

---

*TrustScan — Map and protect your digital business.* 🛡️