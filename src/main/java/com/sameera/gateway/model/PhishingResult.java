package com.sameera.gateway.model;

/**
 * Represents the result of phishing analysis from Llama AI
 */
public class PhishingResult {
    private final double phishingProbability;
    private final String riskLevel;
    private final String explanation;
    private final String[] indicators;
    
    public PhishingResult(double phishingProbability, String riskLevel, String explanation, String[] indicators) {
        this.phishingProbability = phishingProbability;
        this.riskLevel = riskLevel;
        this.explanation = explanation;
        this.indicators = indicators != null ? indicators : new String[0];
    }
    
    public double getPhishingProbability() {
        return phishingProbability;
    }
    
    public String getRiskLevel() {
        return riskLevel;
    }
    
    public String getExplanation() {
        return explanation;
    }
    
    public String[] getIndicators() {
        return indicators;
    }
    
    public boolean isHighRisk() {
        return phishingProbability > 0.7;
    }
    
    public boolean isMediumRisk() {
        return phishingProbability > 0.4 && phishingProbability <= 0.7;
    }
    
    public boolean isLowRisk() {
        return phishingProbability <= 0.4;
    }
    
    @Override
    public String toString() {
        return String.format("PhishingResult{probability=%.2f, risk=%s, explanation='%s'}", 
                           phishingProbability, riskLevel, explanation);
    }
}