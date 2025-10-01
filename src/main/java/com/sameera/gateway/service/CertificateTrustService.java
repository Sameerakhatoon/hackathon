package com.sameera.gateway.service;

import com.sameera.gateway.model.CertificateScore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

/**
 * Enhanced Certificate Trust Scoring Service
 * 
 * This service analyzes SSL/TLS certificates with comprehensive scoring,
 * providing detailed trust analysis based on multiple sophisticated factors.
 */
@Service
public class CertificateTrustService {
    
    private static final Logger logger = LoggerFactory.getLogger(CertificateTrustService.class);
    
    // Premium/High-Trust Certificate Authorities (40 points)
    private static final Set<String> PREMIUM_CAS = Set.of(
        "DigiCert Inc",
        "VeriSign",
        "Symantec Corporation",
        "GlobalSign",
        "Entrust",
        "IdenTrust",
        "QuoVadis"
    );
    
    // Standard/Established Certificate Authorities (30 points)
    private static final Set<String> STANDARD_CAS = Set.of(
        "Google Trust Services",
        "Microsoft Corporation",
        "Amazon",
        "Sectigo Limited",
        "GeoTrust Inc",
        "Thawte",
        "RapidSSL",
        "GoDaddy",
        "Cloudflare"
    );
    
    // Basic/Free Certificate Authorities (20 points)
    private static final Set<String> BASIC_CAS = Set.of(
        "Let's Encrypt",
        "Comodo",
        "SSL.com",
        "ZeroSSL",
        "cPanel"
    );
    
    // Suspicious/Risky patterns (5 points)
    private static final Set<String> SUSPICIOUS_ISSUERS = Set.of(
        "Self-Signed",
        "localhost",
        "test",
        "example",
        "internal"
    );
    
    /**
     * Score the trustworthiness of a website's SSL certificate
     */
    public CertificateScore scoreWebsite(String domain) {
    logger.info("🔐 [START] Analyzing certificate for domain: {}", domain);
        
        try {
            logger.debug("🔐 Preparing to retrieve certificate for domain: {}", domain);
            String fullUrl = domain;
            if (!domain.startsWith("https://")) {
                fullUrl = "https://" + domain;
            }
            
            String cleanDomain = domain.replace("https://", "").replace("http://", "").split("/")[0];
            
            X509Certificate cert = getCertificate(fullUrl);
            if (cert == null) {
                logger.warn("🔐 No certificate found for domain: {}", cleanDomain);
                CertificateScore score = createLowTrustScore(cleanDomain, "Could not retrieve certificate");
                logger.info("🔐 [END] Certificate analysis result for {}: {}", cleanDomain, score);
                return score;
            }
            logger.debug("🔐 Certificate retrieved for domain: {}", cleanDomain);
            CertificateScore score = analyzeCertificate(cert, cleanDomain);
            logger.info("🔐 [END] Certificate analysis result for {}: {}", cleanDomain, score);
            return score;
            
        } catch (Exception e) {
            logger.error("❌ Exception during certificate analysis for {}: {}", domain, e);
            String cleanDomain = domain.replace("https://", "").replace("http://", "").split("/")[0];
            CertificateScore score = createLowTrustScore(cleanDomain, "Certificate analysis failed: " + e.getMessage());
            logger.info("🔐 [END] Fallback certificate analysis result for {}: {}", cleanDomain, score);
            return score;
        }
    }
    
    /**
     * Retrieve the SSL certificate from a domain
     */
    private X509Certificate getCertificate(String urlString) {
    logger.debug("🔐 Attempting to retrieve SSL certificate from: {}", urlString);
    try {
            // Create a trust manager that accepts all certificates (for analysis only)
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            
            java.net.URI uri = java.net.URI.create(urlString);
            HttpsURLConnection conn = (HttpsURLConnection) uri.toURL().openConnection();
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.setHostnameVerifier((hostname, session) -> true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();
            
            Certificate[] certs = conn.getServerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                return (X509Certificate) certs[0];
            }
            
        } catch (Exception e) {
            logger.warn("Could not retrieve certificate for {}: {}", urlString, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Analyze certificate details and assign trust score with comprehensive analysis
     */
    private CertificateScore analyzeCertificate(X509Certificate cert, String domain) {
        int score = 50; // Start from 50 (neutral) and adjust up/down
        boolean isExpired = false;
        boolean isSelfSigned = false;
        String issuer = cert.getIssuerX500Principal().getName();
        Date expiryDate = cert.getNotAfter();
        Date issuedDate = cert.getNotBefore();
        Date now = new Date();
        LocalDateTime expiration = expiryDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
        int certificateAge = (int) ((now.getTime() - issuedDate.getTime()) / (1000 * 60 * 60 * 24));
        Map<String, Object> additionalInfo = new HashMap<>();
        
        // 1. CRITICAL CHECKS - Immediate disqualifiers
        if (expiryDate.before(now)) {
            score = 5; // Expired certificates get minimal score
            isExpired = true;
            logger.warn("❌ Certificate EXPIRED for {}: {}", domain, expiryDate);
            additionalInfo.put("expired_days", (now.getTime() - expiryDate.getTime()) / (1000 * 60 * 60 * 24));
            return createCertificateScore(score, domain, isExpired, isSelfSigned, false, false, 
                                        certificateAge, issuer, expiration, additionalInfo);
        }
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            score = 15; // Self-signed gets very low score
            isSelfSigned = true;
            logger.warn("❌ SELF-SIGNED certificate for {}", domain);
            additionalInfo.put("self_signed", true);
            return createCertificateScore(score, domain, isExpired, isSelfSigned, false, false, 
                                        certificateAge, issuer, expiration, additionalInfo);
        }
        
        // 2. CERTIFICATE AUTHORITY ANALYSIS (30 points max) - Adjusted for neutral start
        int caScore = analyzeCertificateAuthority(issuer, domain);
        score += caScore;
        boolean isValidCA = caScore > 15;

        // 3. DOMAIN VALIDATION ANALYSIS (20 points max) - Adjusted for neutral start
        int domainScore = analyzeDomainValidation(cert, domain);
        score += domainScore;
        boolean domainMatches = domainScore > 8;
        
        // 4. CERTIFICATE CHAIN & EXTENSIONS (10 points max) - Adjusted for neutral start
        score += analyzeCertificateExtensions(cert, domain);
        
        // 5. ISSUER REPUTATION CHECK (5 points max) - Adjusted for neutral start
        score += analyzeIssuerReputation(issuer, domain);

        // 6. Key strength (new)
        int keyStrength = 0;
        try {
            int keyLength = cert.getPublicKey().getEncoded().length * 8; // bytes to bits
            additionalInfo.put("key_length_bits", keyLength);
            if (keyLength < 2048) {
                score -= 15;
                keyStrength = -15;
                additionalInfo.put("weak_key", true);
            } else if (keyLength < 3072) {
                score += 5;
                keyStrength = 5;
            } else {
                score += 10;
                keyStrength = 10;
            }
        } catch (Exception e) {
            additionalInfo.put("key_length_error", e.getMessage());
        }

        // 7. SAN entries (Subject Alternative Names)
        try {
            Collection<List<?>> sanList = cert.getSubjectAlternativeNames();
            if (sanList != null) {
                additionalInfo.put("san_count", sanList.size());
                int unrelatedSan = 0;
                for (List<?> san : sanList) {
                    if (san.size() > 1 && san.get(1) instanceof String) {
                        String sanDomain = ((String) san.get(1)).toLowerCase();
                        if (!sanDomain.endsWith(domain.toLowerCase()) && !domain.toLowerCase().endsWith(sanDomain)) {
                            unrelatedSan++;
                        }
                    }
                }
                if (unrelatedSan > 2) {
                    score -= 10;
                    additionalInfo.put("unrelated_san", unrelatedSan);
                }
            }
        } catch (Exception e) {
            additionalInfo.put("san_error", e.getMessage());
        }

        // 8. Wildcard certificate abuse (e.g., *.com, *.xyz)
        try {
            String subject = cert.getSubjectX500Principal().getName();
            String cn = extractCommonName(subject);
            if (cn != null && cn.startsWith("*.") && (cn.equals("*.com") || cn.equals("*.xyz") || cn.equals("*.net"))) {
                score -= 20;
                additionalInfo.put("suspicious_wildcard", cn);
            }
        } catch (Exception e) {
            additionalInfo.put("wildcard_error", e.getMessage());
        }

        // 9. Placeholder: Revocation status (CRL/OCSP)
        // TODO: Implement CRL/OCSP check for revocation status
        additionalInfo.put("revocation_status", "not_checked");

        // 10. Placeholder: TLS version support
        // TODO: Implement TLS version probing for server
        additionalInfo.put("tls_version", "not_checked");
        
        // Add additional information
        additionalInfo.put("key_algorithm", cert.getPublicKey().getAlgorithm());
        additionalInfo.put("signature_algorithm", cert.getSigAlgName());
        additionalInfo.put("serial_number", cert.getSerialNumber().toString());
        additionalInfo.put("certificate_age_days", certificateAge);
        additionalInfo.put("ca_score", caScore);
        additionalInfo.put("domain_score", domainScore);
        // Check for weak algorithms
        String sigAlgorithm = cert.getSigAlgName().toLowerCase();
        if (sigAlgorithm.contains("md5") || sigAlgorithm.contains("sha1")) {
            score -= 10;
            additionalInfo.put("weak_signature", true);
        }
        // Final score bounds and adjustments
        score = Math.max(5, Math.min(100, score));
        logger.info("\uD83D\uDD12 Certificate score for {}: {} (issuer: {}, expires: {})", 
                   domain, score, extractCAName(issuer), expiryDate);
        return createCertificateScore(score, domain, isExpired, isSelfSigned, isValidCA, domainMatches, 
                                    certificateAge, issuer, expiration, additionalInfo);
    }
    
    /**
     * Analyze Certificate Authority trustworthiness
     */
    private int analyzeCertificateAuthority(String issuer, String domain) {
        String issuerUpper = issuer.toUpperCase();
        
        // Check for suspicious issuers first
        for (String suspicious : SUSPICIOUS_ISSUERS) {
            if (issuerUpper.contains(suspicious.toUpperCase())) {
                logger.warn("🚨 SUSPICIOUS issuer for {}: {}", domain, issuer);
                return 5; // Very low score
            }
        }
        
        // Check premium CAs
        for (String ca : PREMIUM_CAS) {
            if (issuerUpper.contains(ca.toUpperCase())) {
                logger.info("💎 PREMIUM CA for {}: {}", domain, ca);
                return 30; // Maximum CA score
            }
        }
        
        // Check standard CAs
        for (String ca : STANDARD_CAS) {
            if (issuerUpper.contains(ca.toUpperCase())) {
                logger.info("✅ STANDARD CA for {}: {}", domain, ca);
                return 25;
            }
        }
        
        // Check basic CAs
        for (String ca : BASIC_CAS) {
            if (issuerUpper.contains(ca.toUpperCase())) {
                logger.info("🆓 BASIC CA for {}: {}", domain, ca);
                return 20;
            }
        }
        
        // Unknown CA
        logger.warn("❓ UNKNOWN CA for {}: {}", domain, issuer);
        return 10;
    }
    
    
    /**
     * Analyze domain validation in certificate
     */
    private int analyzeDomainValidation(X509Certificate cert, String domain) {
        try {
            String subject = cert.getSubjectX500Principal().getName();
            String cn = extractCommonName(subject);
            
            if (cn == null) {
                logger.warn("⚠️  No Common Name in certificate for {}", domain);
                return 5;
            }
            
            // Check SAN (Subject Alternative Names) first - more reliable for CDN certificates
            Collection<List<?>> sanList = cert.getSubjectAlternativeNames();
            if (sanList != null) {
                for (List<?> san : sanList) {
                    if (san.size() > 1 && san.get(1) instanceof String) {
                        String sanDomain = ((String) san.get(1)).toLowerCase();
                        if (sanDomain.equals(domain.toLowerCase())) {
                            logger.info("✅ Perfect SAN match for {}: {}", domain, sanDomain);
                            return 20;
                        }
                        if (sanDomain.startsWith("*.") && domain.toLowerCase().endsWith(sanDomain.substring(2))) {
                            logger.info("🔗 Valid wildcard SAN for {}: {}", domain, sanDomain);
                            return 15;
                        }
                    }
                }
            }
            
            // Check for wildcard certificates
            if (cn.startsWith("*.")) {
                if (domain.endsWith(cn.substring(2))) {
                    logger.info("🔗 Valid wildcard certificate for {}: {}", domain, cn);
                    return 15; // Wildcard is fine but slightly less secure
                } else {
                    logger.warn("🚨 Invalid wildcard certificate for {}: {}", domain, cn);
                    return 5;
                }
            }
            
            // Exact domain match
            if (cn.equalsIgnoreCase(domain)) {
                logger.info("✅ Perfect domain match for {}", domain);
                return 20;
            }
            
            // Check for CDN patterns (e.g., cdn-dynmedia-1.microsoft.com vs secure4s.scene7.com)
            if (isCDNDomain(domain) && isCDNCertificate(cn)) {
                logger.info("🌐 CDN certificate detected for {}: {}", domain, cn);
                return 12; // CDN certificates are acceptable but not perfect
            }
            
            // Check for domain variations
            if (cn.toLowerCase().contains(domain.toLowerCase()) || 
                domain.toLowerCase().contains(cn.toLowerCase())) {
                logger.info("🔗 Domain variation match for {}: {}", domain, cn);
                return 15;
            }
            
            logger.warn("❌ Domain mismatch for {}: certificate is for {}", domain, cn);
            return 5;
            
        } catch (Exception e) {
            logger.warn("⚠️  Error analyzing domain validation for {}: {}", domain, e.getMessage());
            return 5;
        }
    }
    
    /**
     * Check if domain is a CDN domain
     */
    private boolean isCDNDomain(String domain) {
        String[] cdnPatterns = {"cdn-", "static-", "assets-", "media-", "images-", "js-", "css-"};
        for (String pattern : cdnPatterns) {
            if (domain.toLowerCase().contains(pattern)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if certificate is from a CDN provider
     */
    private boolean isCDNCertificate(String cn) {
        String[] cdnProviders = {"scene7", "cloudfront", "akamai", "fastly", "cloudflare", "maxcdn"};
        for (String provider : cdnProviders) {
            if (cn.toLowerCase().contains(provider)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Analyze certificate extensions and usage
     */
    private int analyzeCertificateExtensions(X509Certificate cert, String domain) {
        try {
            // Check for Extended Validation (EV) certificates and extensions
            Set<String> nonCriticalExtensions = cert.getNonCriticalExtensionOIDs();
            
            int extensionScore = 5; // Base score
            
            // Look for key usage extensions
            if (nonCriticalExtensions != null && nonCriticalExtensions.contains("2.5.29.15")) {
                extensionScore += 2; // Has key usage extension
            }
            
            // Look for Subject Alternative Name
            if (nonCriticalExtensions != null && nonCriticalExtensions.contains("2.5.29.17")) {
                extensionScore += 3; // Has SAN extension
            }
            
            return Math.min(extensionScore, 10);
            
        } catch (Exception e) {
            return 5; // Default score on error
        }
    }
    
    /**
     * Additional issuer reputation analysis
     */
    private int analyzeIssuerReputation(String issuer, String domain) {
        String issuerUpper = issuer.toUpperCase();
        
        // Look for regional/national CAs that might be trustworthy
        String[] regionalCAs = {"GOVERNMENT", "GOV", "NATIONAL", "STATE", "BANK", "FINANCIAL"};
        for (String regional : regionalCAs) {
            if (issuerUpper.contains(regional)) {
                logger.info("🏛️  Regional/Government CA detected for {}", domain);
                return 8;
            }
        }
        
        // Look for academic institutions
        String[] academicCAs = {"UNIVERSITY", "EDUCATION", "EDU", "RESEARCH"};
        for (String academic : academicCAs) {
            if (issuerUpper.contains(academic)) {
                logger.info("🎓 Academic CA detected for {}", domain);
                return 7;
            }
        }
        
        return 5; // Default reputation score
    }
    
    /**
     * Extract Common Name from certificate subject
     */
    private String extractCommonName(String subject) {
        String[] parts = subject.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return null;
    }
    
    /**
     * Extract clean CA name from issuer DN
     */
    private String extractCAName(String issuer) {
        // Try to extract O= (Organization) first, then CN=
        String[] parts = issuer.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("O=")) {
                return part.substring(2);
            }
        }
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return issuer; // Fallback to full issuer
    }
    
    /**
     * Create a CertificateScore object with proper constructor
     */
    private CertificateScore createCertificateScore(int score, String domain, boolean isExpired, 
                                                   boolean isSelfSigned, boolean isValidCA, 
                                                   boolean domainMatches, int certificateAge, 
                                                   String issuer, LocalDateTime expiration,
                                                   Map<String, Object> additionalInfo) {
        return new CertificateScore(score, domain, isExpired, isSelfSigned, isValidCA, 
                                   domainMatches, certificateAge, issuer, expiration, additionalInfo);
    }
    
    /**
     * Create a low trust score for error cases
     */
    private CertificateScore createLowTrustScore(String domain, String reason) {
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("error", reason);
        
        return new CertificateScore(
            10, // Very low score
            domain,
            true, // Assume expired if we can't check
            false,
            false,
            false,
            0,
            "Unknown - " + reason,
            LocalDateTime.now(),
            additionalInfo
        );
    }
}