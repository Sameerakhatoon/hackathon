package com.sameera.gateway.controller;

import com.sameera.gateway.service.BlocklistService;
import com.sameera.gateway.service.WhitelistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.HashMap;

/**
 * Status Controller for health checks and API information
 */
@RestController
public class StatusController {
    
    @Autowired
    private BlocklistService blocklistService;
    
    @Autowired
    private WhitelistService whitelistService;
    
    @GetMapping("/")
    public Map<String, Object> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("name", "Anti-Phishing AI Gateway");
        response.put("version", "1.0.0");
        response.put("description", "Java-based AI-powered gateway for phishing detection");
        response.put("author", "Sameera Khatoon");
        response.put("hackathon", "FutureStack GenAI Hackathon 2025");
        response.put("sponsor_technologies", Map.of(
            "Meta", "Llama LLM for phishing detection",
            "Cerebras", "API hosting for ultra-fast AI inference", 
            "Docker", "Docker Compose for containerization"
        ));
        response.put("timestamp", LocalDateTime.now());
        response.put("status", "running");
        
        Map<String, String> usage = new HashMap<>();
        usage.put("proxy", "Configure your browser proxy to http://localhost:8080");
        usage.put("test_api", "GET /proxy?url=https://example.com");
        usage.put("health", "GET /actuator/health");
        response.put("usage", usage);
        
        return response;
    }
    
    @GetMapping("/actuator/health")
    public Map<String, Object> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("timestamp", LocalDateTime.now());
        
        Map<String, Object> components = new HashMap<>();
        components.put("proxy", Map.of("status", "UP"));
        components.put("phishing_detector", Map.of("status", "UP"));
        components.put("cert_scorer", Map.of("status", "UP"));
        components.put("decision_engine", Map.of("status", "UP"));
        response.put("components", components);
        
        return response;
    }
    
    @GetMapping("/api/system-stats")
    public Map<String, Object> stats() {
        Map<String, Object> response = new HashMap<>();
        response.put("threatsBlocked", 0); // TODO: Implement counter
        response.put("warningsIssued", 0); // TODO: Implement counter
        response.put("sitesAllowed", 0); // TODO: Implement counter
        response.put("aiAnalyses", 0); // TODO: Implement counter
        response.put("blocklistCount", blocklistService.getBlocklistSize());
        response.put("whitelistCount", whitelistService.getWhitelistSize());
        response.put("timestamp", LocalDateTime.now());
        
        return response;
    }
}