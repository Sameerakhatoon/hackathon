# 🛡️ Anti-Phishing AI Web Gateway

  

> **🏆 Built for FutureStack GenAI Hackathon 2025**  

> Leveraging cutting-edge AI technology from Meta, Cerebras and Docker for enterprise-grade phishing protection

  

---

  

## 🎯 Project Overview

  

The **Anti-Phishing AI Web Gateway** is a sophisticated, containerized security system that could have prevented the **18 NPM packages breach** that shook the developer world in September 2025. This devastating supply-chain attack compromised 2+ billion weekly downloads through a simple phishing email targeting a maintainer's account.

  

### 🚨 **Why This Matters: Real-World Impact**

  

**Recent NPM Breach (Sept 8-9, 2025):** Attackers phished developer credentials, compromised 18 popular packages (chalk, debug, ansi-styles, etc.), and deployed crypto-stealing malware that targeted browsers globally. This **"one person in Skegness"** attack exposed our vulnerable dependency ecosystem.

  

**Our Solution:** Real-time AI-powered protection that could have:

- 🔍 **Detected malicious domains** like `npmjs[.]help` (the phishing domain)

- 🛡️ **Blocked suspicious redirects** before users reached compromised sites

- ⚡ **Prevented the 2+ billion downloads** from reaching vulnerable endpoints

  

Built for the **FutureStack GenAI Hackathon 2025**, our system combines **Meta's Llama 3.1-8B** model with **Cerebras' ultra-fast AI inference** and **Docker** to deliver intelligent, real-time phishing detection with comprehensive certificate analysis and WHOIS intelligence.

  

---

  

## 🚀 Quick Start Installation

  

### 📋 Prerequisites

- **Docker** and **Docker Compose** installed

- **Chrome** browser for testing

- **Internet connection** for AI API calls

  

### 🔧 Step-by-Step Setup

  

#### 1. **Clone and Navigate**

```bash

git clone https://github.com/Sameerakhatoon/hackathon.git

cd hackathon

```

  

#### 2. **Start the System**

```bash

docker-compose up --build

```

This will:

- Build and start the Java AI Gateway (port 8080)

- Build and start mitmproxy (port 8081)

- Create persistent `logs/` directory

- Generate mitmproxy CA certificate

  

#### 3. **Verify System Health**

```bash

# Check Java backend health

curl http://localhost:8080/actuator/health

  

# Check mitmproxy status

curl http://localhost:8081/

```

  

#### 4. **Install Browser Extension**

1. Open Chrome and go to `chrome://extensions/`

2. Enable "Developer mode"

3. Click "Load unpacked" and select the `anti-phishing-gateway-extension` folder

4. The extension will automatically configure proxy settings

  

#### 5. **Install mitmproxy CA Certificate**

```bash

# Extract certificate from container

docker exec mitmproxy-gateway find / -name "mitmproxy-ca-cert.pem"

docker cp mitmproxy-gateway:/root/.mitmproxy/mitmproxy-ca-cert.pem ./logs/mitmproxy-ca-cert.pem

```

  

**Install in Chrome:**

1. Go to `chrome://settings/certificates`

2. Click "Authorities" tab

3. Click "Import" and select `./logs/mitmproxy-ca-cert.pem`

4. Check "Trust this certificate for identifying websites"

5. Click "OK"

  

#### 6. **Test the System**

Visit these URLs to test different scenarios:


- `https://www.google.com/`

- `https://www.amazon.com/`

- `https://onlinesbi.sbi.bank.in/`

- `https://www.unionbankofindia.co.in/`

- `http://www.phishingsite.com/`
  

### 🎯 Expected Behavior

- **Safe sites**: Load normally with green "ALLOWED" logs

- **Suspicious sites**: Show interactive warning/block pages

- **One-click override**: "Add to Whitelist & Retry" button

- **Live monitoring**: View logs at `http://localhost:8080/logs`

  

### 🔍 Troubleshooting

  

**Certificate Issues:**

```bash

# Re-extract certificate if needed

docker cp mitmproxy-gateway:/root/.mitmproxy/mitmproxy-ca-cert.pem ./logs/mitmproxy-ca-cert.pem

```

  

**Proxy Not Working:**

- Check extension is loaded and enabled

- Verify proxy settings point to `localhost:8081`

- Restart browser after certificate installation

  

**AI API Issues:**

- Check internet connection

- Verify Cerebras API key is configured

- Check logs at `http://localhost:8080/logs`

  

---

  

## 🏗️ Architecture

  

```

[Browser] ⇄ [mitmproxy (Docker)] ⇄ [Java AI Gateway (Spring Boot, Docker)] ⇄ [Internet]

```

  

- **Browser**: Configured to use mitmproxy as HTTP/HTTPS proxy (via extension or manual settings)

- **mitmproxy**: Intercepts all traffic, filters non-essential resources, calls the Java backend for AI-based decisions, and serves interactive block/warning pages

- **Java Backend**: Aggregates AI phishing analysis, certificate trust, and WHOIS risk to make security decisions. Provides comprehensive REST APIs for whitelist/blocklist management

- **Docker Compose**: Orchestrates all services, ensures logs and certificates are persisted

  

---

  

## 🧩 Key Components

  

- **mitmproxy (Python, Docker)**: Transparent HTTP/HTTPS proxy, resource filter, AI gateway client, and interactive response pages.

- **Java Backend (Spring Boot)**: Exposes `/ai-check` endpoint, runs phishing/cert/WHOIS analysis, makes final decisions, and provides REST APIs.

- **Browser Extension**: Automatically configures browser proxy settings to point to mitmproxy (localhost:8081).

- **Docker Compose**: Orchestrates mitmproxy and Java backend containers, mounts logs and mitmproxy CA certificate for persistence.

  

## ✨ Key Features

  

### 🤖 **AI-Powered Security**

- **Meta Llama 3.1-8B**: Sophisticated phishing detection with 9 comprehensive rules

- **Cerebras API**: Ultra-fast AI inference with exponential backoff retry logic

- **Intelligent Analysis**: Typosquatting, homoglyph detection, suspicious TLD identification

- **Confidence Scoring**: Real-time probability assessment with detailed explanations

- **Fallback Protection**: Heuristic analysis when AI services are unavailable

  

### 🔒 **Advanced Certificate Analysis**

- **100-Point Scoring**: Comprehensive SSL/TLS certificate trust evaluation

- **Premium CA Recognition**: DigiCert, VeriSign, GlobalSign, and other trusted authorities

- **Domain Validation**: SAN support, wildcard detection, and domain matching

- **Key Strength Analysis**: 2048-bit minimum requirement with algorithm validation

- **Certificate Monitoring**: Age tracking, expiration alerts, and revocation status

  

### 🌐 **WHOIS Intelligence**

- **Enhanced Parsing**: 21 ISO 8601 date formats for accurate domain age calculation

- **Registrar Analysis**: Reputation scoring and suspicious pattern detection

- **Privacy Detection**: Identification of privacy-protected registrations

- **Status Monitoring**: Domain status tracking (HOLD, LOCK, SUSPENDED)

- **Risk Assessment**: Multi-factor domain reputation evaluation

  

### 📱 **Interactive Management**

- **Modern UI**: Rich HTML block/warning pages with seamless user experience

- **One-Click Whitelist**: "Add to Whitelist & Retry" functionality

- **Smart Management**: Automatic blocklist removal when whitelisting URLs

- **Bulk Operations**: Clear all lists with confirmation dialogs

- **Real-Time Updates**: Live statistics and monitoring dashboard

  

### 🔧 **Enterprise Features**

- **REST APIs**: Full CRUD operations for whitelist/blocklist management

- **Live Logging**: Real-time log streaming with Server-Sent Events

- **Health Monitoring**: System status endpoints and comprehensive diagnostics

- **Docker Integration**: Easy deployment with Docker Compose orchestration

- **Browser Extension**: Zero-configuration proxy setup for Chrome

  

---

  

## 📊 How It Works

  

### 🔄 **Request Flow**

1. **Browser** sends request via proxy to mitmproxy

2. **mitmproxy** filters static resources (CSS, JS, images) and analyzes main HTML pages

3. **AI Analysis** calls Java backend `/ai-check` endpoint with URL

4. **Multi-Factor Analysis**:

   - **🤖 PhishingDetectionService**: Meta Llama 3.1-8B via Cerebras API

   - **🔒 CertificateTrustService**: 100-point SSL/TLS certificate scoring

   - **🌐 DomainWhoisService**: Enhanced WHOIS analysis with 21 date formats

   - **🧠 DecisionEngineService**: Weighted risk assessment (50% AI, 30% cert, 20% WHOIS)

  

### 🎯 **Decision Making**

5. **Risk Assessment**: Combines all factors into comprehensive risk score

6. **Decision Response**:

   - **ALLOW**: Low risk - forwards request to destination

   - **WARN**: Medium risk - serves interactive warning page

   - **BLOCK**: High risk - serves interactive block page

  

### 🎨 **Interactive Experience**

7. **Rich UI**: Modern HTML pages with detailed explanations

8. **One-Click Override**: "Add to Whitelist & Retry" button

9. **Smart Management**: Automatic blocklist removal when whitelisting

10. **Real-Time Updates**: Live statistics and monitoring dashboard

  

### 📈 **Monitoring & Logging**

11. **Comprehensive Logging**: Detailed activity logs with emoji indicators

12. **Live Dashboard**: Real-time log streaming at `/logs`

13. **Health Monitoring**: System status and performance metrics

14. **Audit Trail**: Complete request/response logging for security analysis

  

---

  

## 🛡️ Security & Logging

- All logs are persisted and rotated in `logs/`.

- mitmproxy CA certificate must be installed in the browser/system for HTTPS interception.

- No sensitive data is stored; only logs of decisions and requests.

- Enhanced WHOIS parsing with ISO 8601 date format support.

  

## 🔧 API Endpoints

  

### 🎯 **Core Security APIs**

- **`POST /ai-check`** - Main AI analysis endpoint (used by mitmproxy)

- **`GET /proxy/**`** - Direct proxy endpoint for testing

- **`GET /actuator/health`** - System health status

  

### 📋 **Management APIs**

- **`GET /api/whitelist`** - Get all whitelisted URLs

- **`POST /api/whitelist/add`** - Add URL to whitelist

- **`DELETE /api/whitelist/remove`** - Remove URL from whitelist

- **`POST /api/whitelist/clear`** - Clear entire whitelist

- **`GET /api/blocklist`** - Get all blocked URLs

- **`POST /api/blocklist/add`** - Add URL to blocklist

- **`DELETE /api/blocklist/remove`** - Remove URL from blocklist

- **`POST /api/blocklist/clear`** - Clear entire blocklist

  

### 📊 **Monitoring APIs**

- **`GET /api/logs`** - View live logs (HTML format)

- **`GET /api/logs/stream`** - Real-time log streaming (Server-Sent Events)

- **`GET /api/stats`** - System statistics and metrics

- **`GET /logs`** - Interactive logs dashboard (web UI)

  

---

  

## 🙏 Acknowledgments

  

### 🏆 **Hackathon Sponsors**

- **[Meta](https://meta.ai/)** - Llama 3.1-8B model for intelligent phishing detection

- **[Cerebras](https://cerebras.ai/)** - Ultra-fast AI inference API hosting

- **[Docker](https://docker.com/)** - Containerization and orchestration platform

- **[Spring Boot](https://spring.io/projects/spring-boot)** - Enterprise-grade Java backend framework

  

### 🛠️ **Open Source Technologies**

- **mitmproxy** - Transparent HTTP/HTTPS proxying

- **Spring Framework** - Enterprise Java development

- **Docker Compose** - Multi-container orchestration

- **Thymeleaf** - Server-side Java template engine

  

---

  

**🏆 Built with ❤️ by Sameera Khatoon for FutureStack GenAI Hackathon 2025**  

**Powered by:** Meta Llama + Cerebras AI + Docker + Spring Boot
