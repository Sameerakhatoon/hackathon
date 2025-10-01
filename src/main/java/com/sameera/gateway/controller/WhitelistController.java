package com.sameera.gateway.controller;

import com.sameera.gateway.service.WhitelistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/whitelist")
public class WhitelistController {
    
    @Autowired
    private WhitelistService whitelistService;
    
    /**
     * Check if a URL is whitelisted
     */
    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> checkUrl(@RequestParam String url) {
        boolean isWhitelisted = whitelistService.isWhitelisted(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);
        response.put("whitelisted", isWhitelisted);
        response.put("message", isWhitelisted ? "URL is whitelisted" : "URL is not whitelisted");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Add URL to whitelist
     */
    @PostMapping("/add")
    public ResponseEntity<Map<String, Object>> addUrl(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        
        if (url == null || url.trim().isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("success", false);
            error.put("message", "URL is required");
            return ResponseEntity.badRequest().body(error);
        }
        
        boolean added = whitelistService.addToWhitelist(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", added);
        response.put("url", url);
        response.put("message", added ? "URL added to whitelist" : "URL already in whitelist");
        response.put("totalWhitelisted", whitelistService.getWhitelistSize());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Remove URL from whitelist
     */
    @DeleteMapping("/remove")
    public ResponseEntity<Map<String, Object>> removeUrl(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        
        if (url == null || url.trim().isEmpty()) {
            Map<String, Object> error = new HashMap<>();
            error.put("success", false);
            error.put("message", "URL is required");
            return ResponseEntity.badRequest().body(error);
        }
        
        boolean removed = whitelistService.removeFromWhitelist(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", removed);
        response.put("url", url);
        response.put("message", removed ? "URL removed from whitelist" : "URL not found in whitelist");
        response.put("totalWhitelisted", whitelistService.getWhitelistSize());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get all whitelisted URLs
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> getAllWhitelistedUrls() {
        Set<String> whitelistedUrls = whitelistService.getAllWhitelistedUrls();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("whitelistedUrls", whitelistedUrls);
        response.put("totalCount", whitelistedUrls.size());
        response.put("message", "Retrieved " + whitelistedUrls.size() + " whitelisted URLs");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get all whitelisted URLs (alternative endpoint for logs page)
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> getWhitelist() {
        Set<String> whitelistedUrls = whitelistService.getAllWhitelistedUrls();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("urls", whitelistedUrls);
        response.put("totalCount", whitelistedUrls.size());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get whitelist statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        int totalWhitelisted = whitelistService.getWhitelistSize();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("totalWhitelisted", totalWhitelisted);
        response.put("message", "Whitelist contains " + totalWhitelisted + " URLs");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Clear entire whitelist
     */
    @DeleteMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearWhitelist() {
        int previousCount = whitelistService.getWhitelistSize();
        whitelistService.clearWhitelist();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Cleared " + previousCount + " URLs from whitelist");
        response.put("totalWhitelisted", 0);
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Clear entire whitelist (POST method for logs page)
     */
    @PostMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearWhitelistPost() {
        int previousCount = whitelistService.getWhitelistSize();
        whitelistService.clearWhitelist();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Cleared " + previousCount + " URLs from whitelist");
        response.put("totalWhitelisted", 0);
        
        return ResponseEntity.ok(response);
    }
}
