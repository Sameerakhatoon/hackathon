# 🛡️ Anti-Phishing AI Web Gateway

> **🏆 Built for FutureStack GenAI Hackathon 2025**  
> Leveraging cutting-edge AI technology from Meta and Cerebras for enterprise-grade phishing protection

---

## 🎯 Project Overview

The **Anti-Phishing AI Web Gateway** is a sophisticated, containerized security system that protects users from phishing attacks through real-time web traffic analysis. Built for the **FutureStack GenAI Hackathon 2025**, it combines **Meta's Llama 3.1-8B** model with **Cerebras' ultra-fast AI inference** to deliver intelligent, real-time phishing detection with comprehensive certificate analysis and WHOIS intelligence.

### 🏆 **Hackathon Sponsors & Technologies**
- **🤖 [Meta](https://meta.ai/)**: Llama 3.1-8B model for intelligent phishing detection
- **⚡ [Cerebras](https://cerebras.ai/)**: Ultra-fast AI inference API hosting  
- **🐳 [Docker](https://docker.com/)**: Containerization and orchestration platform
- **☕ [Spring Boot](https://spring.io/projects/spring-boot)**: Enterprise-grade Java backend framework

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
- **Browser Extension**: Zero-configuration proxy setup for Chrome/Edge

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