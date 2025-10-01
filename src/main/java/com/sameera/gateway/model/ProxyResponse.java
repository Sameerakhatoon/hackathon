package com.sameera.gateway.model;

/**
 * Represents the response from the proxy service
 */
public class ProxyResponse {
    private final SecurityDecision decision;
    private final String targetUrl;
    private final String content;
    private final int statusCode;
    
    public ProxyResponse(SecurityDecision decision, String targetUrl) {
        this(decision, targetUrl, null, 200);
    }
    
    public ProxyResponse(SecurityDecision decision, String targetUrl, String content, int statusCode) {
        this.decision = decision;
        this.targetUrl = targetUrl;
        this.content = content;
        this.statusCode = statusCode;
    }
    
    public SecurityDecision getDecision() {
        return decision;
    }
    
    public String getTargetUrl() {
        return targetUrl;
    }
    
    public String getContent() {
        return content;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
    
    public boolean isBlocked() {
        return decision.getAction() == SecurityAction.BLOCK;
    }
    
    public boolean requiresWarning() {
        return decision.getAction() == SecurityAction.WARN;
    }
    
    public boolean isAllowed() {
        return decision.getAction() == SecurityAction.ALLOW;
    }
}