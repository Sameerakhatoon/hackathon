package com.sameera.gateway.model;

import java.time.LocalDateTime;

/**
 * Represents a security decision made by the gateway
 */
public class SecurityDecision {
    private final SecurityAction action;
    private final String reason;
    private final String llamaExplanation;
    private final double confidence;
    private final LocalDateTime timestamp;
    
    public SecurityDecision(SecurityAction action, String reason) {
        this(action, reason, null, 1.0);
    }
    
    public SecurityDecision(SecurityAction action, String reason, String llamaExplanation, double confidence) {
        this.action = action;
        this.reason = reason;
        this.llamaExplanation = llamaExplanation;
        this.confidence = confidence;
        this.timestamp = LocalDateTime.now();
    }
    
    public SecurityAction getAction() {
        return action;
    }
    
    public String getReason() {
        return reason;
    }
    
    public String getLlamaExplanation() {
        return llamaExplanation;
    }
    
    public double getConfidence() {
        return confidence;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    @Override
    public String toString() {
        return String.format("SecurityDecision{action=%s, reason='%s', confidence=%.2f}", 
                           action, reason, confidence);
    }
}