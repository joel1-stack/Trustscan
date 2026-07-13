# TrustScan - Digital Trust Intelligence Platform

A comprehensive Digital Trust Intelligence Platform that continuously maps, verifies, and evaluates an organization's externally visible digital trust posture. Built for Kenyan SMEs and beyond.

## 🎯 Overview

TrustScan helps organizations understand their digital exposure by scanning publicly visible assets associated with their domain and providing an actionable Trust Score with detailed remediation guidance.

### Key Features

- **Passive Reconnaissance** - Only queries public data sources, never touches customer infrastructure
- **Permission-Based Scanning** - Requires explicit domain ownership verification before scanning
- **Comprehensive Coverage** - 13 intelligence layers from DNS to breach intelligence
- **Actionable Scoring** - Weighted scoring across 6 dimensions with prioritized remediation
- **Kenyan Context** - Built-in Kenya DPA compliance, CBK guidelines, local threat intelligence
- **TrustLayer Integration** - API for transaction risk assessment
- **Global Support** - Works with any TLD (.com, .org, .co.ke, etc.) and email addresses

## 🏗️ Architecture

TrustScan follows a 7-engine pipeline architecture:

```
Domain Input
    │
    ▼
┌─────────────────┐
│  DISCOVERY      │  ← Finds everything that exists (DNS, Certificates, WHOIS)
│  ENGINE         │
└────────┬────────┘
         │ DiscoveryMap
         ▼
┌─────────────────┐
│  RECONNAISSANCE │  ← Inspects every asset for security properties
│  ENGINE         │
└────────┬────────┘
         │ RawSignal[] (500+ signals)
         ▼
┌─────────────────┐
│  NORMALIZATION  │  ← Converts all formats into one language
│  ENGINE         │
└────────┬────────┘
         │ NormalizedSignal[]
         ▼
┌─────────────────┐
│  CORRELATION    │  ← Connects signals into patterns
│  ENGINE         │
└────────┬────────┘
         │ Correlation[]
         ▼
┌─────────────────┐
│  SCORING        │  ← Converts patterns into numbers
│  ENGINE         │
└────────┬────────┘
         │ TrustScore
         ▼
┌─────────────────┐
│  INTELLIGENCE   │  ← Adds context, benchmarks, predictions
│  ENGINE         │
└────────┬────────┘
         │ IntelligenceBrief
         ▼
┌─────────────────┐
│  REPORTING      │  ← Produces all output formats
│  ENGINE         │
└─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Redis (for Celery)
- PostgreSQL (production) or SQLite (development)

### Installation

```bash
# Clone the repository
git clone https://github.com/joel1-stack/Trustscan.git
cd Trustscan

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your settings

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Start development server
python manage.py runserver
```

### Starting Celery Workers

```bash
# Terminal 1: Celery worker (all queues)
celery -A config worker --pool=solo -l info

# Terminal 2: Celery beat (scheduler)
celery -A config beat -l info

# Terminal 3: Redis (if not running)
redis-server
```

## 📁 Project Structure

```
Trustscan/
├── config/                 # Django project configuration
├── apps/
│   ├── core/              # Shared utilities, base models
│   ├── accounts/          # User management, organizations, teams
│   ├── domains/           # Domain management & authorization
│   ├── scanner/           # Scan orchestration & job management
│   ├── discovery/         # Engine 1: Discovery Engine
│   ├── reconnaissance/    # Engine 2: Reconnaissance Engine
│   ├── correlation/       # Engine 3: Correlation Engine
│   ├── scoring/           # Engine 4: Scoring Engine
│   ├── intelligence/      # Engine 5: Intelligence Engine
│   ├── reports/           # Engine 6: Reporting Engine
│   ├── billing/           # Subscriptions & M-Pesa integration
│   ├── api/               # External API (TrustLayer integration)
│   └── dashboard/         # Admin dashboard
├── workers/               # Celery configuration
├── external/              # Third-party API wrappers
├── templates/             # Global Django templates
├── static/                # CSS, JS, images
├── docs/                  # Documentation
├── tests/                 # Test suite
└── scripts/               # Management commands
```

## 🔧 Configuration

### Environment Variables

```env
# Django
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (SQLite for dev)
DATABASE_URL=sqlite:///db.sqlite3

# Redis & Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
REDIS_URL=redis://localhost:6379/2

# Email
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# External APIs
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
HIBP_API_KEY=
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
SECURITYTRAILS_API_KEY=
GITHUB_TOKEN=

# M-Pesa
MPESA_CONSUMER_KEY=
MPESA_CONSUMER_SECRET=
MPESA_SHORTCODE=
MPESA_PASSKEY=
MPESA_CALLBACK_URL=
MPESA_ENVIRONMENT=sandbox
```

## 📊 Intelligence Layers

| Layer | Source | What It Finds |
|-------|--------|---------------|
| DNS Intelligence | Public DNS resolvers | MX, A, TXT, SPF, DKIM, DMARC, DNSSEC |
| Certificate Intelligence | crt.sh, CertSpotter | All historical SSL certificates, subdomains |
| Domain Intelligence | WHOIS/RDAP | Registrar, expiry, privacy protection |
| Asset Discovery | Passive DNS, Shodan | IPs, CDNs, cloud providers, exposed origin |
| Technology Detection | HTTP headers, HTML | Server software, frameworks, CMS |
| Email Security | DNS records | SPF, DKIM, DMARC, BIMI, MTA-STS |
| HTTP Security | HTTP headers | HSTS, CSP, X-Frame-Options, cookies |
| Reputation Intelligence | Google Safe Browsing, Spamhaus | Blacklists, malware, phishing |
| Breach Intelligence | HaveIBeenPwned, DeHashed | Leaked emails, credentials |
| Cloud Intelligence | IP ranges, headers | AWS, Azure, GCP, S3 buckets |
| GitHub Intelligence | GitHub API | Public repos, secrets, CI/CD configs |
| API Intelligence | HTTP discovery | Swagger, GraphQL, unauthenticated endpoints |

## 📈 Scoring Dimensions

| Dimension | Weight | Focus |
|-----------|--------|-------|
| Email Security | 20% | SPF, DKIM, DMARC configuration |
| Infrastructure Hygiene | 15% | SSL validity, DNSSEC, TLS versions |
| Exposure Surface | 15% | Subdomains, admin panels, open ports |
| Breach History | 15% | Leaked credentials, past compromises |
| Reputation & Trust | 15% | Blacklists, domain age, spam scores |
| Identity Integrity | 20% | WHOIS accuracy, domain expiry, registrar |

## 🔐 Authorization Flow

1. User adds domain (e.g., `company.co.ke`)
2. System generates verification token
3. User proves ownership via:
   - **DNS TXT Record** (primary) - Add `trustscan-verify=<token>`
   - **HTML File** - Upload `trustscan_<token>.html` to web root
   - **Meta Tag** - Add `<meta name="trustscan-verification" content="<token>">`
   - **Email** - Click link sent to admin@/webmaster@/postmaster@
4. Domain marked `AUTHORIZED` - scanning permitted
5. User can revoke authorization anytime

## 📡 API Integration (TrustLayer)

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

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=apps --cov-report=html

# Run specific test
pytest tests/unit/test_scoring.py -v
```

## 📚 Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api_reference.md)
- [Scoring Rules](docs/scoring_rules.md)
- [Deployment Guide](docs/deployment.md)

## 🚢 Deployment

### Docker (Recommended)

```bash
docker-compose up -d
```

### Manual Production

```bash
# Set production settings
export DEBUG=False
export ALLOWED_HOSTS=api.trustscan.co.ke,trustscan.co.ke

# Run with Gunicorn
gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 4

# Run Celery with proper pool
celery -A config worker -Q orchestration,discovery,reconnaissance,correlation,scoring,intelligence,reporting,billing,api,domains,accounts --pool=prefork --concurrency=4

# Run Celery Beat
celery -A config beat
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

Proprietary - TrustScan Digital Trust Intelligence Platform

## 📞 Support

- Email: support@trustscan.co.ke
- Documentation: https://docs.trustscan.co.ke
- Status: https://status.trustscan.co.ke

---

**TrustScan** — Map and protect your digital business. 🛡️