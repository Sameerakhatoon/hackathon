package com.sameera.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sameera.gateway.model.PhishingResult;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Phishing Detection Service using Meta Llama via Cerebras API
 * 
 * This service sends URLs and content to Meta's Llama model hosted on Cerebras
 * for intelligent phishing detection and natural language explanations.
 */
@Service
public class PhishingDetectionService {
    
    private static final Logger logger = LoggerFactory.getLogger(PhishingDetectionService.class);
    
    @Value("${cerebras.api.url:https://api.cerebras.ai/v1/chat/completions}")
    private String cerebrasApiUrl;
    
    @Value("${cerebras.api.key:}")
    private String cerebrasApiKey;
    
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    public PhishingDetectionService() {
        this.httpClient = new OkHttpClient.Builder().build();
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Analyze a URL for phishing using Llama via Cerebras API
     */
    public PhishingResult analyzeUrl(String url) {
    logger.info("🧠 [START] Analyzing URL for phishing: {}", url);
        
        try {
            logger.debug("🧠 Preparing to analyze URL: {}", url);
            // If API key is not configured, use simple heuristic analysis
            if (cerebrasApiKey == null || cerebrasApiKey.trim().isEmpty()) {
                logger.warn("⚠️  Cerebras API key not configured, using heuristic analysis");
                PhishingResult result = analyzeUrlHeuristic(url);
                logger.info("🧠 [END] Heuristic analysis result for {}: {}", url, result);
                return result;
            }
            
            // Create prompt for Llama
            logger.debug("🧠 Creating prompt for Llama for URL: {}", url);
            String prompt = createPhishingPrompt(url);
            
            // Call Cerebras API
            logger.debug("🧠 Calling Cerebras API for URL: {}", url);
            String response = callCerebrasApi(prompt);
            
            // Parse response
            logger.debug("🧠 Parsing Cerebras API response for URL: {}", url);
            PhishingResult result = parsePhishingResponse(response, url);
            logger.info("🧠 [END] Cerebras analysis result for {}: {}", url, result);
            return result;
            
        } catch (Exception e) {
            logger.error("❌ Exception during phishing analysis for {}: {}", url, e);
            // Fallback to heuristic analysis
            PhishingResult result = analyzeUrlHeuristic(url);
            logger.info("🧠 [END] Fallback heuristic analysis result for {}: {}", url, result);
            return result;
        }
    }
    
    /**
     * Create a comprehensive prompt for Llama to analyze phishing with sophisticated detection
     */
    private String createPhishingPrompt(String url) {
        return String.format(
            "Analyze the following URL for phishing using ONLY URL-based signals (do NOT use WHOIS, domain age, or page content): %s\n\n" +
            "Return EXACTLY this JSON: {\"risk_level\": \"<LOW|MEDIUM|HIGH>\", \"probability\": <0.0-1.0>, \"explanation\": \"<concise, evidence-based reasoning>\", \"indicators\": [\"<list of specific indicators found>\"]}\n\n" +
            "Apply these rules:\n" +
            "1) Typosquatting/homoglyph detection: Check for visual or edit-distance similarity to popular brands.\n" +
            "2) Suspicious/free TLDs: Flag .tk, .ml, .ga, .cf, .gq, and new gTLDs.\n" +
            "3) IP-literal host or uncommon port.\n" +
            "4) Excessive subdomains (brand-as-subdomain form).\n" +
            "5) Obfuscated URL structure: long/encoded paths, base64 tokens.\n" +
            "6) Keywords: login/account/verify/update in path/query, especially with brand name.\n" +
            "7) Userinfo in URL (user:pass@host).\n" +
            "8) Blacklist match (if available).\n" +
            "9) Known phishing patterns (IDN tricks, directory mimicking login).\n" +
            "Explain findings concisely. List all concrete indicators in 'indicators' array. Probability should be calibrated (not always 1.0 for suspicious, unless multiple red flags).\n",
            url
        );
    }
    
    /**
     * Call Cerebras API with the prompt and retry logic for rate limiting
     */
    private String callCerebrasApi(String prompt) throws IOException {
        return callCerebrasApiWithRetry(prompt, 0);
    }
    
    /**
     * Call Cerebras API with exponential backoff retry logic
     */
    private String callCerebrasApiWithRetry(String prompt, int attempt) throws IOException {
        logger.debug("🔗 Constructing request body for Cerebras API (attempt {})", attempt + 1);
        String requestBody = String.format(
            "{\n" +
            "  \"model\": \"llama3.1-8b\",\n" +
            "  \"messages\": [\n" +
            "    {\n" +
            "      \"role\": \"user\",\n" +
            "      \"content\": \"%s\"\n" +
            "    }\n" +
            "  ],\n" +
            "  \"max_completion_tokens\": 500,\n" +
            "  \"temperature\": 0.3\n" +
            "}", prompt.replace("\"", "\\\"").replace("\n", "\\n"));
        
        Request request = new Request.Builder()
            .url(cerebrasApiUrl)
            .post(RequestBody.create(requestBody, MediaType.get("application/json")))
            .addHeader("Authorization", "Bearer " + cerebrasApiKey)
            .addHeader("Content-Type", "application/json")
            .build();
        logger.debug("🔗 Sending request to Cerebras API: {} (attempt {})", cerebrasApiUrl, attempt + 1);
        
        try (Response response = httpClient.newCall(request).execute()) {
            logger.debug("🔗 Cerebras API response code: {} (attempt {})", response.code(), attempt + 1);
            
            if (response.code() == 429 && attempt < 3) {
                // Rate limited - retry with exponential backoff
                long delayMs = (long) Math.pow(2, attempt) * 1000; // 1s, 2s, 4s
                logger.warn("⏳ Rate limited (429), retrying in {}ms (attempt {})", delayMs, attempt + 1);
                Thread.sleep(delayMs);
                return callCerebrasApiWithRetry(prompt, attempt + 1);
            }
            
            if (!response.isSuccessful()) {
                logger.error("❌ Cerebras API call failed: {} (attempt {})", response.code(), attempt + 1);
                throw new IOException("Cerebras API call failed: " + response.code());
            }
            
            String body = response.body().string();
            logger.debug("🔗 Cerebras API response body: {}", body);
            return body;
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Request interrupted during retry", e);
        }
    }
    
    /**
     * Parse the response from Cerebras API with enhanced analysis
     */
    private PhishingResult parsePhishingResponse(String apiResponse, String url) {
    logger.debug("🧠 Parsing API response for URL: {}", url);
    try {
            JsonNode root = objectMapper.readTree(apiResponse);
            JsonNode choices = root.get("choices");
            
            if (choices != null && choices.isArray() && choices.size() > 0) {
                String content = choices.get(0).get("message").get("content").asText();
                
                // Log the raw response for debugging
                logger.debug("🧠 Raw Llama response for {}: {}", url, content);
                
                // Try to parse JSON from the content
                try {
                    // Sometimes the response contains markdown or extra text, extract just the JSON
                    String jsonContent = extractJsonFromResponse(content);
                    JsonNode analysis = objectMapper.readTree(jsonContent);
                    
                    String riskLevel = analysis.get("risk_level").asText();
                    double probability = analysis.get("probability").asDouble();
                    String explanation = analysis.get("explanation").asText();
                    
                    List<String> indicators = new ArrayList<>();
                    JsonNode indicatorNode = analysis.get("indicators");
                    if (indicatorNode != null && indicatorNode.isArray()) {
                        for (JsonNode indicator : indicatorNode) {
                            indicators.add(indicator.asText());
                        }
                    }
                    
                    // Add additional analysis fields if present
                    String attackType = analysis.has("attack_type") ? analysis.get("attack_type").asText() : "";
                    String targetBrand = analysis.has("target_brand") ? analysis.get("target_brand").asText() : "";
                    String confidence = analysis.has("confidence") ? analysis.get("confidence").asText() : "";
                    
                    if (!attackType.isEmpty()) {
                        indicators.add("Attack Type: " + attackType);
                    }
                    if (!targetBrand.isEmpty()) {
                        indicators.add("Target Brand: " + targetBrand);
                    }
                    if (!confidence.isEmpty()) {
                        indicators.add("AI Confidence: " + confidence);
                    }
                    
                    logger.info("🎯 Parsed phishing analysis for {}: {} ({}% confidence)", url, riskLevel, (int)(probability * 100));
                    
                    return new PhishingResult(probability, riskLevel, explanation, indicators.toArray(new String[0]));
                    
                } catch (Exception e) {
                    logger.warn("⚠️  JSON parsing failed for {}, using textual analysis: {}", url, e);
                    // If JSON parsing fails, extract info from text
                    return parseTextualResponse(content, url);
                }
            }
            
        } catch (Exception e) {
            logger.error("❌ Error parsing Cerebras response for {}: {}", url, e);
        }
        
        // Fallback
        return new PhishingResult(0.2, "LOW", "Analysis completed with basic heuristics due to parsing error", new String[]{"Fallback analysis used"});
    }
    
    /**
     * Extract JSON content from potentially formatted response
     */
    private String extractJsonFromResponse(String content) {
        // Look for JSON between curly braces
        int startIndex = content.indexOf('{');
        int endIndex = content.lastIndexOf('}');
        
        if (startIndex != -1 && endIndex != -1 && endIndex > startIndex) {
            return content.substring(startIndex, endIndex + 1);
        }
        
        return content; // Return original if no JSON structure found
    }
    
    /**
     * Enhanced textual response parsing for when JSON parsing fails
     */
    private PhishingResult parseTextualResponse(String content, String url) {
        double probability = 0.1;
        String riskLevel = "LOW";
        List<String> indicators = new ArrayList<>();
        
        String contentLower = content.toLowerCase();
        
        // Enhanced risk detection patterns
        if (contentLower.contains("high risk") || contentLower.contains("definitely phishing") || 
            contentLower.contains("clearly phishing") || contentLower.contains("obvious phishing") ||
            contentLower.contains("dangerous") || contentLower.contains("malicious")) {
            probability = 0.85;
            riskLevel = "HIGH";
        } else if (contentLower.contains("medium risk") || contentLower.contains("possibly phishing") ||
                   contentLower.contains("likely phishing") || contentLower.contains("suspicious") ||
                   contentLower.contains("potentially dangerous")) {
            probability = 0.5;
            riskLevel = "MEDIUM";
        } else if (contentLower.contains("low risk") || contentLower.contains("legitimate") ||
                   contentLower.contains("safe") || contentLower.contains("not phishing")) {
            probability = 0.1;
            riskLevel = "LOW";
        }
        
        // Extract specific indicators mentioned in text
        if (contentLower.contains("typosquatting")) indicators.add("Typosquatting detected");
        if (contentLower.contains("suspicious tld") || contentLower.contains(".tk") || contentLower.contains(".ml")) {
            indicators.add("Suspicious TLD");
        }
        if (contentLower.contains("brand impersonation")) indicators.add("Brand impersonation");
        if (contentLower.contains("subdomain abuse")) indicators.add("Subdomain abuse");
        if (contentLower.contains("new domain")) indicators.add("New domain registration");
        if (contentLower.contains("homograph")) indicators.add("Homograph attack");
        if (contentLower.contains("url shortener")) indicators.add("URL shortener detected");
        
        // Look for probability numbers in text
        try {
            if (contentLower.contains("probability")) {
                String[] words = content.split("\\s+");
                for (int i = 0; i < words.length; i++) {
                    if (words[i].toLowerCase().contains("probability") && i + 1 < words.length) {
                        String nextWord = words[i + 1].replaceAll("[^0-9.]", "");
                        if (!nextWord.isEmpty()) {
                            double textProbability = Double.parseDouble(nextWord);
                            if (textProbability <= 1.0) {
                                probability = textProbability;
                            } else if (textProbability <= 100) {
                                probability = textProbability / 100.0;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors for probability extraction
        }
        
        if (indicators.isEmpty()) {
            indicators.add("Textual analysis performed");
        }
        
        logger.info("📝 Textual analysis for {}: {} ({}% confidence)", url, riskLevel, (int)(probability * 100));
        
        return new PhishingResult(probability, riskLevel, content, indicators.toArray(new String[0]));
    }
    
    /**
     * Fallback heuristic analysis when API is not available
     */
    private PhishingResult analyzeUrlHeuristic(String urlString) {
        try {
            java.net.URI uri = java.net.URI.create(urlString);
            String domain = uri.getHost().toLowerCase();
            List<String> indicators = new ArrayList<>();
            double suspiciousScore = 0.0;
            
            // Check for suspicious patterns
            if (domain.contains("paypal") && !domain.equals("paypal.com")) {
                indicators.add("Suspicious PayPal domain");
                suspiciousScore += 0.4;
            }
            
            if (domain.contains("amazon") && !domain.equals("amazon.com") && !domain.endsWith(".amazon.com")) {
                indicators.add("Suspicious Amazon domain");
                suspiciousScore += 0.4;
            }
            
            if (domain.contains("microsoft") && !domain.endsWith("microsoft.com")) {
                indicators.add("Suspicious Microsoft domain");
                suspiciousScore += 0.4;
            }
            
            if (domain.contains("google") && !domain.endsWith("google.com") && !domain.endsWith("googleapis.com")) {
                indicators.add("Suspicious Google domain");
                suspiciousScore += 0.4;
            }
            
            // Check for suspicious TLDs
            String[] suspiciousTlds = {".tk", ".ml", ".ga", ".cf"};
            for (String tld : suspiciousTlds) {
                if (domain.endsWith(tld)) {
                    indicators.add("Suspicious TLD: " + tld);
                    suspiciousScore += 0.3;
                    break;
                }
            }
            
            // Check for excessive subdomains
            String[] parts = domain.split("\\.");
            if (parts.length > 4) {
                indicators.add("Excessive subdomains");
                suspiciousScore += 0.2;
            }
            
            // Check for URL shorteners (could be hiding destination)
            String[] shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl"};
            for (String shortener : shorteners) {
                if (domain.equals(shortener)) {
                    indicators.add("URL shortener detected");
                    suspiciousScore += 0.1;
                    break;
                }
            }
            
            // Determine risk level
            String riskLevel;
            if (suspiciousScore >= 0.7) {
                riskLevel = "HIGH";
            } else if (suspiciousScore >= 0.3) {
                riskLevel = "MEDIUM";
            } else {
                riskLevel = "LOW";
            }
            
            String explanation = indicators.isEmpty() ? 
                "No obvious phishing indicators detected" : 
                "Detected potential phishing indicators: " + String.join(", ", indicators);
            
            return new PhishingResult(suspiciousScore, riskLevel, explanation, indicators.toArray(new String[0]));
            
        } catch (Exception e) {
            logger.error("Error in heuristic analysis: {}", e.getMessage());
            return new PhishingResult(0.0, "LOW", "Analysis failed: " + e.getMessage(), new String[0]);
        }
    }
}