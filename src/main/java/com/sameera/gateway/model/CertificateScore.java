package com.sameera.gateway.model;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Represents the trust score and analysis of an SSL certificate
 */
public class CertificateScore {
    private final int score;              // 0-100 trust score
    private final String domain;
    private final boolean isExpired;
    private final boolean isSelfSigned;
    private final boolean isValidCA;
    private final boolean domainMatches;
    private final int certificateAge;     // in days
    private final String issuer;
    private final LocalDateTime expiration;
    private final Map<String, Object> additionalInfo;
    
    public CertificateScore(int score, String domain, boolean isExpired, 
                           boolean isSelfSigned, boolean isValidCA, 
                           boolean domainMatches, int certificateAge, 
                           String issuer, LocalDateTime expiration,
                           Map<String, Object> additionalInfo) {
        this.score = Math.max(0, Math.min(100, score)); // Ensure 0-100 range
        this.domain = domain;
        this.isExpired = isExpired;
        this.isSelfSigned = isSelfSigned;
        this.isValidCA = isValidCA;
        this.domainMatches = domainMatches;
        this.certificateAge = certificateAge;
        this.issuer = issuer;
        this.expiration = expiration;
        this.additionalInfo = additionalInfo;
    }
    
    public int getScore() {
        return score;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public boolean isExpired() {
        return isExpired;
    }
    
    public boolean isSelfSigned() {
        return isSelfSigned;
    }
    
    public boolean isValidCA() {
        return isValidCA;
    }
    
    public boolean isDomainMatches() {
        return domainMatches;
    }
    
    public int getCertificateAge() {
        return certificateAge;
    }
    
    public String getIssuer() {
        return issuer;
    }
    
    public LocalDateTime getExpiration() {
        return expiration;
    }
    
    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }
    
    public boolean isHighTrust() {
        return score >= 80;
    }
    
    public boolean isMediumTrust() {
        return score >= 50 && score < 80;
    }
    
    public boolean isLowTrust() {
        return score < 50;
    }
    
    @Override
    public String toString() {
        return String.format("CertificateScore{domain='%s', score=%d, issuer='%s', expired=%b}", 
                           domain, score, issuer, isExpired);
    }
}