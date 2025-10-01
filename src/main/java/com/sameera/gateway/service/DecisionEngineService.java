package com.sameera.gateway.service;

import com.sameera.gateway.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Decision Engine Service
 * 
 * This service combines phishing analysis and certificate trust scores
 * to make intelligent decisions about whether to allow, warn, or block requests.
 */
@Service
public class DecisionEngineService {
    
    private static final Logger logger = LoggerFactory.getLogger(DecisionEngineService.class);
    
    // Thresholds for decision making - Adjusted for legitimate sites
    private static final double HIGH_PHISHING_THRESHOLD = 0.5;  // Block at 50% instead of 70%
    private static final double MEDIUM_PHISHING_THRESHOLD = 0.2; // Warn at 20% instead of 40%
    private static final int LOW_CERT_TRUST_THRESHOLD = 40;      // Adjusted for new scoring system
    private static final int MEDIUM_CERT_TRUST_THRESHOLD = 70;   // Adjusted for new scoring system
    
    // WHOIS-based risk thresholds
    private static final int VERY_NEW_DOMAIN_DAYS = 30;          // Domains younger than 30 days are high risk
    private static final int NEW_DOMAIN_DAYS = 90;               // Domains younger than 90 days are medium risk
    private static final int MATURE_DOMAIN_DAYS = 365;           // Domains older than 1 year are low risk
    
    private final DomainWhoisService domainWhoisService = new DomainWhoisService();
    
    /**
     * Make a security decision based on phishing analysis and certificate trust score
     */
    public SecurityDecision makeDecision(PhishingResult phishingResult, CertificateScore certScore, String url) {
    logger.info("🤔 [START] Making decision for {} - Phishing: {}, Cert: {}", 
           url, phishingResult.getPhishingProbability(), certScore.getScore());
        
    double phishingProbability = phishingResult.getPhishingProbability();
    int trustScore = certScore.getScore();
    logger.debug("🤔 Phishing probability: {}, Cert trust score: {}", phishingProbability, trustScore);
        
        // Extract domain for WHOIS analysis
        String domain = url.replaceFirst("^https?://", "").split("/|\\?")[0];
        logger.debug("🔍 Extracted domain for analysis: {}", domain);
        
        // WHOIS-based risk assessment
        DomainWhoisInfo whoisInfo = domainWhoisService.getWhoisInfo(domain);
        double whoisRiskScore = assessWhoisRisk(whoisInfo);
        logger.info("🔍 WHOIS risk assessment for {}: score={}", domain, whoisRiskScore);
        // Combine all risk factors for comprehensive assessment
        double combinedRisk = calculateCombinedRisk(phishingProbability, trustScore, whoisRiskScore);
        logger.debug("🤔 Combined risk score: {}", combinedRisk);
        
        // High-risk scenarios - BLOCK
        if (phishingProbability >= HIGH_PHISHING_THRESHOLD || whoisRiskScore >= 0.8 || combinedRisk >= 0.7) {
            String blockReason = buildBlockReason(phishingProbability, trustScore, whoisRiskScore, whoisInfo);
            SecurityDecision decision = new SecurityDecision(
                SecurityAction.BLOCK,
                blockReason,
                enhanceExplanationWithWhois(phishingResult.getExplanation(), whoisInfo),
                combinedRisk
            );
            logger.info("🤔 [END] Decision for {}: BLOCK - {}", url, blockReason);
            return decision;
        }
        
        if (trustScore <= LOW_CERT_TRUST_THRESHOLD || (trustScore <= MEDIUM_CERT_TRUST_THRESHOLD && whoisRiskScore >= 0.6)) {
            String reason = buildCertificateBlockReason(trustScore, certScore, whoisRiskScore, whoisInfo);
            String fullExplanation = enhanceExplanationWithWhois(phishingResult.getExplanation(), whoisInfo);
            if (fullExplanation == null || fullExplanation.trim().isEmpty() || 
                fullExplanation.equals("Certificate security issues detected")) {
                fullExplanation = reason + ". AI analysis: " + 
                    (phishingProbability > 0.5 ? "High phishing risk detected" : "Low phishing risk, blocked due to certificate and domain issues");
            }
            SecurityDecision decision = new SecurityDecision(
                SecurityAction.BLOCK,
                reason,
                fullExplanation,
                Math.max(combinedRisk, 1.0 - (trustScore / 100.0))
            );
            logger.info("🤔 [END] Decision for {}: BLOCK (cert trust) - {}", url, reason);
            return decision;
        }
        
        // Combination of medium risks - BLOCK
        if (phishingProbability >= MEDIUM_PHISHING_THRESHOLD && trustScore <= MEDIUM_CERT_TRUST_THRESHOLD) {
            String reason = String.format("Combined risk: Medium phishing probability (%.1f%%) + Low certificate trust (%d/100)", 
                            phishingProbability * 100, trustScore);
            SecurityDecision decision = new SecurityDecision(
                SecurityAction.BLOCK,
                reason,
                phishingResult.getExplanation(),
                (phishingProbability + (1.0 - trustScore / 100.0)) / 2.0
            );
            logger.info("🤔 [END] Decision for {}: BLOCK (combined medium) - {}", url, reason);
            return decision;
        }
        
        // Medium-risk scenarios - WARN
        if (phishingProbability >= MEDIUM_PHISHING_THRESHOLD || whoisRiskScore >= 0.5 || combinedRisk >= 0.4) {
            String warnReason = buildWarnReason(phishingProbability, trustScore, whoisRiskScore, whoisInfo);
            SecurityDecision decision = new SecurityDecision(
                SecurityAction.WARN,
                warnReason,
                enhanceExplanationWithWhois(phishingResult.getExplanation(), whoisInfo),
                combinedRisk
            );
            logger.info("🤔 [END] Decision for {}: WARN - {}", url, warnReason);
            return decision;
        }
        
        if (trustScore <= MEDIUM_CERT_TRUST_THRESHOLD) {
            String reason = String.format("Medium certificate trust score (%d/100)", trustScore);
            List<String> issues = new ArrayList<>();
            if (!certScore.isValidCA()) {
                issues.add("unknown CA");
            }
            if (!certScore.isDomainMatches()) {
                issues.add("domain mismatch");
            }
            if (!issues.isEmpty()) {
                reason += " - " + String.join(", ", issues);
            }
            SecurityDecision decision = new SecurityDecision(
                SecurityAction.WARN,
                reason,
                "Certificate has some trust issues but may be legitimate",
                0.5
            );
            logger.info("🤔 [END] Decision for {}: WARN (cert trust) - {}", url, reason);
            return decision;
        }
        
        
        // Low-risk scenarios - ALLOW
        String allowReason = String.format("Low risk: Phishing probability %.1f%%, Certificate trust %d/100", 
                                          phishingProbability * 100, trustScore);
        SecurityDecision decision = new SecurityDecision(
            SecurityAction.ALLOW,
            allowReason,
            "No significant security concerns detected",
            Math.max(phishingProbability, 1.0 - trustScore / 100.0)
        );
        logger.info("🤔 [END] Decision for {}: ALLOW - {}", url, allowReason);
        return decision;
    }
    
    /**
     * Get a human-readable risk assessment summary
     */
    public String getRiskSummary(PhishingResult phishingResult, CertificateScore certScore) {
        StringBuilder summary = new StringBuilder();
        
        // Phishing assessment
        summary.append("🔍 Phishing Analysis: ").append(phishingResult.getRiskLevel());
        if (phishingResult.getIndicators().length > 0) {
            summary.append(" (").append(String.join(", ", phishingResult.getIndicators())).append(")");
        }
        summary.append("\n");
        
        // Certificate assessment
        summary.append("🔐 Certificate Trust: ");
        if (certScore.isHighTrust()) {
            summary.append("HIGH");
        } else if (certScore.isMediumTrust()) {
            summary.append("MEDIUM");
        } else {
            summary.append("LOW");
        }
        summary.append(" (").append(certScore.getScore()).append("/100)");
        
        if (certScore.isExpired()) {
            summary.append(" - EXPIRED");
        }
        if (certScore.isSelfSigned()) {
            summary.append(" - SELF-SIGNED");
        }
        
        return summary.toString();
    }
    
    /**
     * Assess WHOIS-based risk factors
     */
    private double assessWhoisRisk(DomainWhoisInfo whoisInfo) {
        if (whoisInfo == null) {
            return 0.3; // Moderate risk if WHOIS data unavailable
        }
        
        double riskScore = 0.0;
        
        // Domain age factor (40% weight)
        long domainAge = whoisInfo.getDomainAgeDays();
        if (domainAge >= 0) {
            if (domainAge < VERY_NEW_DOMAIN_DAYS) {
                riskScore += 0.4; // Very new domains are high risk
            } else if (domainAge < NEW_DOMAIN_DAYS) {
                riskScore += 0.25; // New domains are medium risk
            } else if (domainAge < MATURE_DOMAIN_DAYS) {
                riskScore += 0.1; // Moderately aged domains are low risk
            }
            // Domains older than 1 year add no risk
        } else {
            riskScore += 0.2; // Unknown age is moderate risk
        }
        
        // Privacy protection factor (20% weight)
        if (whoisInfo.isPrivacyProtected()) {
            riskScore += 0.2;
        }
        
        // Registrar reputation factor (20% weight)
        String registrar = whoisInfo.getRegistrar();
        if (registrar != null) {
            if (isSuspiciousRegistrar(registrar)) {
                riskScore += 0.2;
            }
        } else {
            riskScore += 0.1; // Unknown registrar is slight risk
        }
        
        // Domain status factor (20% weight)
        String status = whoisInfo.getDomainStatus();
        if (status != null && (status.contains("HOLD") || status.contains("LOCK") || status.contains("SUSPENDED"))) {
            riskScore += 0.2;
        }
        
        return Math.min(riskScore, 1.0);
    }
    
    /**
     * Check if registrar is known to be suspicious
     */
    private boolean isSuspiciousRegistrar(String registrar) {
        String lowerRegistrar = registrar.toLowerCase();
        return lowerRegistrar.contains("privacy") || 
               lowerRegistrar.contains("proxy") ||
               lowerRegistrar.contains("anonymous") ||
               lowerRegistrar.contains("cheap") ||
               lowerRegistrar.contains("free");
    }
    
    /**
     * Calculate combined risk score from all factors
     */
    private double calculateCombinedRisk(double phishingProbability, int trustScore, double whoisRiskScore) {
        // Weighted combination: 50% phishing, 30% certificate, 20% whois
        double certRisk = 1.0 - (trustScore / 100.0);
        return (phishingProbability * 0.5) + (certRisk * 0.3) + (whoisRiskScore * 0.2);
    }
    
    /**
     * Build comprehensive block reason including WHOIS factors
     */
    private String buildBlockReason(double phishingProbability, int trustScore, double whoisRiskScore, DomainWhoisInfo whoisInfo) {
        List<String> reasons = new ArrayList<>();
        
        if (phishingProbability >= HIGH_PHISHING_THRESHOLD) {
            reasons.add(String.format("High phishing probability (%.1f%%)", phishingProbability * 100));
        }
        
        if (trustScore <= LOW_CERT_TRUST_THRESHOLD) {
            reasons.add(String.format("Low certificate trust (%d/100)", trustScore));
        }
        
        if (whoisRiskScore >= 0.6 && whoisInfo != null) {
            if (whoisInfo.getDomainAgeDays() >= 0 && whoisInfo.getDomainAgeDays() < VERY_NEW_DOMAIN_DAYS) {
                reasons.add(String.format("Very new domain (%d days)", whoisInfo.getDomainAgeDays()));
            }
            if (whoisInfo.isPrivacyProtected()) {
                reasons.add("Privacy-protected registration");
            }
        }
        
        return "High risk: " + String.join(", ", reasons);
    }
    
    /**
     * Build certificate-specific block reason with WHOIS context
     */
    private String buildCertificateBlockReason(int trustScore, CertificateScore certScore, double whoisRiskScore, DomainWhoisInfo whoisInfo) {
        String reason = String.format("Low certificate trust score (%d/100)", trustScore);
        
        if (certScore.isExpired()) {
            reason += " - Certificate expired";
        }
        if (certScore.isSelfSigned()) {
            reason += " - Self-signed certificate";
        }
        
        if (whoisRiskScore >= 0.6 && whoisInfo != null && whoisInfo.getDomainAgeDays() >= 0 && whoisInfo.getDomainAgeDays() < NEW_DOMAIN_DAYS) {
            reason += String.format(" + New domain (%d days)", whoisInfo.getDomainAgeDays());
        }
        
        return reason;
    }
    
    /**
     * Build comprehensive warning reason including WHOIS factors
     */
    private String buildWarnReason(double phishingProbability, int trustScore, double whoisRiskScore, DomainWhoisInfo whoisInfo) {
        List<String> factors = new ArrayList<>();
        
        if (phishingProbability >= MEDIUM_PHISHING_THRESHOLD) {
            factors.add(String.format("Medium phishing risk (%.1f%%)", phishingProbability * 100));
        }
        
        if (trustScore <= MEDIUM_CERT_TRUST_THRESHOLD) {
            factors.add(String.format("Medium certificate trust (%d/100)", trustScore));
        }
        
        if (whoisRiskScore >= 0.4 && whoisInfo != null) {
            if (whoisInfo.getDomainAgeDays() >= 0 && whoisInfo.getDomainAgeDays() < NEW_DOMAIN_DAYS) {
                factors.add(String.format("New domain (%d days)", whoisInfo.getDomainAgeDays()));
            }
            if (whoisInfo.isPrivacyProtected()) {
                factors.add("Privacy-protected registration");
            }
        }
        
        return "Caution advised: " + String.join(", ", factors);
    }
    
    /**
     * Enhance explanation with WHOIS context
     */
    private String enhanceExplanationWithWhois(String originalExplanation, DomainWhoisInfo whoisInfo) {
        if (whoisInfo == null) {
            return originalExplanation;
        }
        
        StringBuilder enhanced = new StringBuilder();
        if (originalExplanation != null && !originalExplanation.trim().isEmpty()) {
            enhanced.append(originalExplanation).append(" ");
        }
        
        List<String> whoisFactors = new ArrayList<>();
        if (whoisInfo.getDomainAgeDays() >= 0) {
            whoisFactors.add(String.format("Domain registered %d days ago", whoisInfo.getDomainAgeDays()));
        }
        if (whoisInfo.isPrivacyProtected()) {
            whoisFactors.add("privacy-protected registration");
        }
        if (whoisInfo.getRegistrar() != null && !whoisInfo.getRegistrar().isEmpty()) {
            whoisFactors.add(String.format("registrar: %s", whoisInfo.getRegistrar()));
        }
        
        if (!whoisFactors.isEmpty()) {
            enhanced.append("Domain info: ").append(String.join(", ", whoisFactors)).append(".");
        }
        
        return enhanced.toString();
    }
}