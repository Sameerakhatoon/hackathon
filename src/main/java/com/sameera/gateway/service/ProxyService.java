package com.sameera.gateway.service;

import com.sameera.gateway.service.LiveLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import okhttp3.*;
import com.sameera.gateway.model.*;
import org.littleshoot.proxy.*;
import org.littleshoot.proxy.impl.DefaultHttpProxyServer;
import io.netty.handler.codec.http.*;
import io.netty.channel.ChannelHandlerContext;
import net.lightbody.bmp.BrowserMobProxy;
import net.lightbody.bmp.BrowserMobProxyServer;
import net.lightbody.bmp.filters.RequestFilter;
import net.lightbody.bmp.filters.ResponseFilter;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.buffer.Unpooled;
import io.netty.util.CharsetUtil;

import java.io.IOException;
import java.net.URI;
import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;
import java.util.Map;
import java.util.HashMap;

/**
 * HTTP/HTTPS Proxy Server Service
 * 
 * This service acts as a transparent proxy that intercepts web traffic
 * and routes it through our AI-powered phishing detection pipeline.
 */
@Service
public class ProxyService {
    
    private static final Logger logger = LoggerFactory.getLogger(ProxyService.class);
    
    @Autowired
    private PhishingDetectionService phishingDetector;
    
    @Autowired
    private CertificateTrustService certificateScorer;
    
    @Autowired
    private DecisionEngineService decisionEngine;
    
    @Autowired
    private LiveLogService liveLogService;
    
    @Autowired
    private BlocklistService blocklistService;
    
    @Autowired
    private WhitelistService whitelistService;
    
    private final OkHttpClient httpClient;
    
    private HttpProxyServer littleProxyServer;

    private BrowserMobProxy browserMobProxy;

    public ProxyService() {
        this.httpClient = new OkHttpClient.Builder()
                .followRedirects(false)
                .build();
    }
    
    /**
     * Process an intercepted web request
     * 
     * @param targetUrl The URL the user is trying to visit
     * @param headers The HTTP headers from the original request
     * @return ProxyResponse containing the decision and any content
     */
    public ProxyResponse processRequest(String targetUrl, Headers headers) {
        logger.info("🔍 [START] Processing request to: {}", targetUrl);
        liveLogService.addLogEntry("INFO", "ProxyService", 
            "🔍 [START] Processing request to: " + targetUrl, Thread.currentThread().getName());
        
        try {
            // First check if URL is in whitelist (fast lookup - bypass all analysis)
            if (whitelistService.isWhitelisted(targetUrl)) {
                logger.info("✅ URL whitelisted, allowing without analysis: {}", targetUrl);
                SecurityDecision allowDecision = new SecurityDecision(
                    SecurityAction.ALLOW, 
                    "URL is in trusted whitelist"
                );
                liveLogService.addLogEntry("INFO", "ProxyService", 
                    "✅ URL whitelisted, allowing without analysis: " + targetUrl, Thread.currentThread().getName());
                return new ProxyResponse(allowDecision, targetUrl);
            }
            
            // Then check if URL is in blocklist (fast lookup)
            if (blocklistService.isBlocked(targetUrl)) {
                logger.info("🚫 URL blocked by blocklist: {}", targetUrl);
                SecurityDecision blockDecision = new SecurityDecision(
                    SecurityAction.BLOCK, 
                    "URL is in phishing blocklist"
                );
                liveLogService.addLogEntry("INFO", "ProxyService", 
                    "🚫 URL blocked by blocklist: " + targetUrl, Thread.currentThread().getName());
                return new ProxyResponse(blockDecision, targetUrl);
            }
            
            logger.debug("🔍 Extracting domain from URL: {}", targetUrl);
            // Extract domain for certificate analysis
            URI uri = new URI(targetUrl);
            String domain = uri.getHost();
            
            // Analyze in parallel for performance
            CompletableFuture<PhishingResult> phishingAnalysis = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        logger.debug("🧠 Starting phishing analysis for: {}", targetUrl);
                        return phishingDetector.analyzeUrl(targetUrl);
                    } catch (Exception e) {
                        logger.error("Error in phishing analysis: {}", e);
                        return new PhishingResult(0.1, "LOW", "Phishing analysis failed: " + e.getMessage(), new String[0]);
                    }
                });
            
            CompletableFuture<CertificateScore> certAnalysis = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        logger.debug("🔐 Starting certificate analysis for: {}", domain);
                        return certificateScorer.scoreWebsite(domain);
                    } catch (Exception e) {
                        logger.error("Error in certificate analysis: {}", e);
                        Map<String, Object> errorInfo = new HashMap<>();
                        errorInfo.put("error", e.getMessage());
                        return new CertificateScore(50, domain, false, false, true, true, 0, "Unknown", 
                                                  LocalDateTime.now(), errorInfo);
                    }
                });
            
            // Wait for both analyses to complete
            PhishingResult phishingResult = phishingAnalysis.get();
            CertificateScore certScore = certAnalysis.get();
            logger.debug("🧠 Phishing analysis result: {}", phishingResult);
            logger.debug("🔐 Certificate analysis result: {}", certScore);
            // Make decision based on combined analysis
            SecurityDecision decision = decisionEngine.makeDecision(phishingResult, certScore, targetUrl);
            // Log the decision
            logger.info("🧠 [END] Decision for {}: {} (Phishing: {}, Cert: {})", 
                       domain, decision.getAction(), 
                       phishingResult.getRiskLevel(), certScore.getScore());
            liveLogService.addLogEntry("INFO", "ProxyService", 
                String.format("🛡️ [END] Decision for %s: %s (Phishing: %s, Cert: %d)", 
                    domain, decision.getAction(), phishingResult.getRiskLevel(), certScore.getScore()),
                Thread.currentThread().getName());
            return new ProxyResponse(decision, targetUrl);
            
        } catch (Exception e) {
            logger.error("❌ Error processing request to {}: {}", targetUrl, e);
            // Default to allowing on error, but log it
            SecurityDecision errorDecision = new SecurityDecision(
                SecurityAction.ALLOW, 
                "Error occurred during analysis: " + e.getMessage()
            );
            liveLogService.addLogEntry("ERROR", "ProxyService", 
                "❌ Error processing request to: " + targetUrl + " - " + e.getMessage(),
                Thread.currentThread().getName());
            return new ProxyResponse(errorDecision, targetUrl);
        }
    }
    
    /**
     * Forward a request to the actual destination (when allowed)
     */
    public Response forwardRequest(String targetUrl, String method, Headers headers, RequestBody body) throws IOException {
        Request.Builder requestBuilder = new Request.Builder()
                .url(targetUrl)
                .headers(headers);
                
        switch (method.toUpperCase()) {
            case "GET":
                requestBuilder.get();
                break;
            case "POST":
                requestBuilder.post(body != null ? body : RequestBody.create("", null));
                break;
            case "PUT":
                requestBuilder.put(body != null ? body : RequestBody.create("", null));
                break;
            case "DELETE":
                requestBuilder.delete();
                break;
            default:
                requestBuilder.method(method, body);
        }
        
        return httpClient.newCall(requestBuilder.build()).execute();
    }
}