package com.sameera.gateway.controller;

import com.sameera.gateway.service.BlocklistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/blocklist")
public class BlocklistController {
    
    @Autowired
    private BlocklistService blocklistService;
    
    /**
     * Check if a URL is blocked
     */
    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> checkUrl(@RequestParam String url) {
        boolean isBlocked = blocklistService.isBlocked(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("url", url);
        response.put("blocked", isBlocked);
        response.put("message", isBlocked ? "URL is blocked" : "URL is not blocked");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Add URL to blocklist
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
        
        boolean added = blocklistService.addToBlocklist(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", added);
        response.put("url", url);
        response.put("message", added ? "URL added to blocklist" : "URL already in blocklist");
        response.put("totalBlocked", blocklistService.getBlocklistSize());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Remove URL from blocklist
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
        
        boolean removed = blocklistService.removeFromBlocklist(url);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", removed);
        response.put("url", url);
        response.put("message", removed ? "URL removed from blocklist" : "URL not found in blocklist");
        response.put("totalBlocked", blocklistService.getBlocklistSize());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get all blocked URLs
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> getAllBlockedUrls() {
        Set<String> blockedUrls = blocklistService.getAllBlockedUrls();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("blockedUrls", blockedUrls);
        response.put("totalCount", blockedUrls.size());
        response.put("message", "Retrieved " + blockedUrls.size() + " blocked URLs");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get all blocked URLs (alternative endpoint for logs page)
     */
    @GetMapping
    public ResponseEntity<Map<String, Object>> getBlocklist() {
        Set<String> blockedUrls = blocklistService.getAllBlockedUrls();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("urls", blockedUrls);
        response.put("totalCount", blockedUrls.size());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Get blocklist statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        int totalBlocked = blocklistService.getBlocklistSize();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("totalBlocked", totalBlocked);
        response.put("message", "Blocklist contains " + totalBlocked + " URLs");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Clear entire blocklist
     */
    @DeleteMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearBlocklist() {
        int previousCount = blocklistService.getBlocklistSize();
        blocklistService.clearBlocklist();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Cleared " + previousCount + " URLs from blocklist");
        response.put("totalBlocked", 0);
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Clear entire blocklist (POST method for logs page)
     */
    @PostMapping("/clear")
    public ResponseEntity<Map<String, Object>> clearBlocklistPost() {
        int previousCount = blocklistService.getBlocklistSize();
        blocklistService.clearBlocklist();
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Cleared " + previousCount + " URLs from blocklist");
        response.put("totalBlocked", 0);
        
        return ResponseEntity.ok(response);
    }
}
