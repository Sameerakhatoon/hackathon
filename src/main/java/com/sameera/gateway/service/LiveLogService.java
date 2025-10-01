package com.sameera.gateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;

/**
 * Live Log Service - Captures and provides application logs for web UI
 */
@Service
public class LiveLogService {
    
    private static final Logger logger = LoggerFactory.getLogger(LiveLogService.class);
    private static final int MAX_LOG_ENTRIES = 500;
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    private final ConcurrentLinkedQueue<LogEntry> logEntries = new ConcurrentLinkedQueue<>();
    private final List<LogListener> listeners = new CopyOnWriteArrayList<>();
    
    // Statistics
    private volatile int threatsBlocked = 0;
    private volatile int warningsIssued = 0;
    private volatile int sitesAllowed = 0;
    private volatile int aiAnalyses = 0;
    
    /**
     * Log entry data structure
     */
    public static class LogEntry {
        private final String timestamp;
        private final String level;
        private final String logger;
        private final String message;
        private final String thread;
        
        public LogEntry(String level, String logger, String message, String thread) {
            this.timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
            this.level = level;
            this.logger = logger;
            this.message = message;
            this.thread = thread;
        }
        
        public String getTimestamp() { return timestamp; }
        public String getLevel() { return level; }
        public String getLogger() { return logger; }
        public String getMessage() { return message; }
        public String getThread() { return thread; }
        
        @Override
        public String toString() {
            return String.format("%s [%s] %-5s %s - %s", timestamp, thread, level, logger, message);
        }
        
        public String toHtml() {
            String cssClass = "log-info";
            if ("ERROR".equals(level)) cssClass = "log-error";
            else if ("WARN".equals(level)) cssClass = "log-warn";
            else if (message.contains("🛡️") || message.contains("🚨") || message.contains("🧠")) cssClass = "log-security";
            
            return String.format("<span class='%s'>%s</span>", cssClass, escapeHtml(toString()));
        }
        
        private String escapeHtml(String text) {
            return text.replace("&", "&amp;")
                      .replace("<", "&lt;")
                      .replace(">", "&gt;")
                      .replace("\"", "&quot;")
                      .replace("'", "&#x27;");
        }
    }
    
    /**
     * Interface for log listeners
     */
    public interface LogListener {
        void onLogEntry(LogEntry entry);
    }
    
    /**
     * Add a log entry
     */
    public void addLogEntry(String level, String loggerName, String message, String thread) {
        logger.debug("📝 [ADD] Log entry: [" + level + "] " + loggerName + " - " + message);
        LogEntry entry = new LogEntry(level, loggerName, message, thread);
        // Update statistics
        updateStatistics(message);
        // Add to queue
        logEntries.offer(entry);
        // Maintain size limit
        while (logEntries.size() > MAX_LOG_ENTRIES) {
            logEntries.poll();
        }
        // Notify listeners
        for (LogListener listener : listeners) {
            try {
                listener.onLogEntry(entry);
            } catch (Exception e) {
                logger.error("Error notifying log listener: " + e.getMessage(), e);
            }
        }
    }
    
    /**
     * Get recent log entries
     */
    public List<LogEntry> getRecentLogs(int limit) {
    logger.debug("📝 [GET] Fetching recent log entries: " + limit);
    return logEntries.stream()
            .skip(Math.max(0, logEntries.size() - limit))
            .toList();
    }
    
    /**
     * Get all log entries as HTML
     */
    public String getLogsAsHtml() {
        StringBuilder html = new StringBuilder();
        for (LogEntry entry : getRecentLogs(100)) {
            html.append(entry.toHtml()).append("\n");
        }
        return html.toString();
    }
    
    /**
     * Add a log listener
     */
    public void addListener(LogListener listener) {
        listeners.add(listener);
    }
    
    /**
     * Remove a log listener
     */
    public void removeListener(LogListener listener) {
        listeners.remove(listener);
    }
    
    /**
     * Update statistics based on log message
     */
    private void updateStatistics(String message) {
        if (message.contains("BLOCK")) {
            threatsBlocked++;
        } else if (message.contains("WARN")) {
            warningsIssued++;
        } else if (message.contains("ALLOW")) {
            sitesAllowed++;
        }
        
        if (message.contains("🧠") || message.contains("Analyzing URL")) {
            aiAnalyses++;
        }
    }
    
    /**
     * Get statistics
     */
    public Statistics getStatistics() {
        return new Statistics(threatsBlocked, warningsIssued, sitesAllowed, aiAnalyses);
    }
    
    /**
     * Statistics data structure
     */
    public static class Statistics {
        private final int threatsBlocked;
        private final int warningsIssued;
        private final int sitesAllowed;
        private final int aiAnalyses;
        
        public Statistics(int threatsBlocked, int warningsIssued, int sitesAllowed, int aiAnalyses) {
            this.threatsBlocked = threatsBlocked;
            this.warningsIssued = warningsIssued;
            this.sitesAllowed = sitesAllowed;
            this.aiAnalyses = aiAnalyses;
        }
        
        public int getThreatsBlocked() { return threatsBlocked; }
        public int getWarningsIssued() { return warningsIssued; }
        public int getSitesAllowed() { return sitesAllowed; }
        public int getAiAnalyses() { return aiAnalyses; }
    }
}