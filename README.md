cat > README.md << 'EOF'
# 🔥 CRAZYX - Ultimate Web Vulnerability Scanner

**539+ Detectors | 48 Phases | Zero-Day Ready | POC Included**

CrazyX is an enterprise-grade web vulnerability scanner written in Go.

## 🚀 Features

### 48 Scanning Phases
- Port scanning (25+ ports)
- Subdomain enumeration (150+ wordlist)
- DNS & email enumeration
- Technology fingerprinting (WAF, CDN, frameworks)
- Directory/file enumeration (350+ paths)
- SQL injection (with encoding fallback)
- XSS (with encoding fallback)
- LFI/RFI
- RCE/Command injection
- SSRF & cloud metadata
- JWT & cookie analysis
- API key discovery (15+ patterns)
- Default credentials testing
- Security headers check
- GraphQL testing
- AI-generated site detection
- NoSQL injection (MongoDB)
- Developer OSINT (60+ patterns)
- Prompt injection (AI chatbots)
- OAuth 2.0 / OIDC testing
- CSP bypass detection
- PostMessage vulnerability scanning
- SAML attack testing
- Cache poisoning detection
- Certificate Transparency subdomains
- ASN enumeration
- HTTP request smuggling
- Prototype pollution
- WebSocket attack testing
- DNS zone transfer (AXFR)
- JWT jku/kid injection
- WebDAV PUT method
- Git repository download
- Kubernetes API exposure
- Prometheus metrics
- Email spoofing analysis (SPF/DKIM/DMARC)
- Jupyter notebook enumeration
- MLflow & Weights & Biases
- Docker registry API
- Elasticsearch exposure
- Redis exposure
- MongoDB exposure
- Memcached exposure
- RabbitMQ management
- Apache status page
- SVN repository exposure
- DS_Store & Thumbs.db exposure

## 📦 Installation

```bash
git clone https://github.com/abubakarmatawalli/crazyX.git
cd crazyX
go build -o crazyx
