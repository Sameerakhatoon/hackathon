package com.sameera.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Service
public class BlocklistService {
    
    private static final Logger logger = LoggerFactory.getLogger(BlocklistService.class);
    
    // In-memory cache for fast lookups
    private final Set<String> blocklist = ConcurrentHashMap.newKeySet();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    
    // File path for persistence
    private static final String BLOCKLIST_FILE = "logs/blocklist.txt";
    
    @PostConstruct
    public void initializeBlocklist() {
        loadBlocklistFromFile();
        logger.info("🚫 Blocklist service initialized with {} URLs", blocklist.size());
    }
    
    /**
     * Check if URL is in blocklist (fast lookup)
     */
    public boolean isBlocked(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.readLock().lock();
        try {
            // Normalize URL for consistent lookup
            String normalizedUrl = normalizeUrl(url);
            boolean blocked = blocklist.contains(normalizedUrl);
            
            if (blocked) {
                logger.info("🚫 URL found in blocklist: {}", url);
            }
            
            return blocked;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Add URL to blocklist
     */
    public boolean addToBlocklist(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.writeLock().lock();
        try {
            String normalizedUrl = normalizeUrl(url);
            boolean added = blocklist.add(normalizedUrl);
            
            if (added) {
                logger.info("➕ Added URL to blocklist: {}", url);
                saveBlocklistToFile();
            }
            
            return added;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Remove URL from blocklist
     */
    public boolean removeFromBlocklist(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.writeLock().lock();
        try {
            String normalizedUrl = normalizeUrl(url);
            boolean removed = blocklist.remove(normalizedUrl);
            
            if (removed) {
                logger.info("➖ Removed URL from blocklist: {}", url);
                saveBlocklistToFile();
            }
            
            return removed;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get all URLs in blocklist
     */
    public Set<String> getAllBlockedUrls() {
        lock.readLock().lock();
        try {
            return new HashSet<>(blocklist);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get blocklist size
     */
    public int getBlocklistSize() {
        lock.readLock().lock();
        try {
            return blocklist.size();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clear entire blocklist
     */
    public void clearBlocklist() {
        lock.writeLock().lock();
        try {
            int size = blocklist.size();
            blocklist.clear();
            logger.info("🗑️ Cleared blocklist (removed {} URLs)", size);
            saveBlocklistToFile();
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Normalize URL for consistent storage and lookup
     */
    private String normalizeUrl(String url) {
        if (url == null) return "";
        
        // Remove protocol if present
        String normalized = url.toLowerCase().trim();
        if (normalized.startsWith("http://")) {
            normalized = normalized.substring(7);
        } else if (normalized.startsWith("https://")) {
            normalized = normalized.substring(8);
        }
        
        // Remove trailing slash
        if (normalized.endsWith("/") && normalized.length() > 1) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        
        // Remove www. prefix for domain-level blocking
        if (normalized.startsWith("www.")) {
            normalized = normalized.substring(4);
        }
        
        return normalized;
    }
    
    /**
     * Load blocklist from file
     */
    private void loadBlocklistFromFile() {
        Path filePath = Paths.get(BLOCKLIST_FILE);
        
        if (!Files.exists(filePath)) {
            logger.info("📄 Blocklist file does not exist, creating empty blocklist");
            createEmptyBlocklistFile();
            return;
        }
        
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            int loaded = 0;
            
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    blocklist.add(line);
                    loaded++;
                }
            }
            
            logger.info("📄 Loaded {} URLs from blocklist file", loaded);
            
        } catch (IOException e) {
            logger.error("❌ Error loading blocklist from file: {}", e.getMessage());
        }
    }
    
    /**
     * Save blocklist to file
     */
    private void saveBlocklistToFile() {
        Path filePath = Paths.get(BLOCKLIST_FILE);
        
        try {
            // Create parent directories if they don't exist
            Files.createDirectories(filePath.getParent());
            
            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write("# Anti-Phishing Gateway Blocklist");
                writer.newLine();
                writer.write("# Format: one URL per line (without http/https)");
                writer.newLine();
                writer.write("# Generated: " + new Date());
                writer.newLine();
                writer.newLine();
                
                // Sort URLs for better readability
                List<String> sortedUrls = new ArrayList<>(blocklist);
                Collections.sort(sortedUrls);
                
                for (String url : sortedUrls) {
                    writer.write(url);
                    writer.newLine();
                }
            }
            
            logger.debug("💾 Saved {} URLs to blocklist file", blocklist.size());
            
        } catch (IOException e) {
            logger.error("❌ Error saving blocklist to file: {}", e.getMessage());
        }
    }
    
    /**
     * Create empty blocklist file with header
     */
    private void createEmptyBlocklistFile() {
        Path filePath = Paths.get(BLOCKLIST_FILE);
        
        try {
            Files.createDirectories(filePath.getParent());
            
            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write("# Anti-Phishing Gateway Blocklist");
                writer.newLine();
                writer.write("# Format: one URL per line (without http/https)");
                writer.newLine();
                writer.write("# Generated: " + new Date());
                writer.newLine();
                writer.newLine();
            }
            
        } catch (IOException e) {
            logger.error("❌ Error creating empty blocklist file: {}", e.getMessage());
        }
    }
}
