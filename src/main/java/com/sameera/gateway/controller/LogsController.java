package com.sameera.gateway.controller;

import com.sameera.gateway.service.LiveLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Logs Controller - Web-based log viewing
 */
@Controller
public class LogsController {
    
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final LiveLogService liveLogService;
    
    @Autowired
    public LogsController(LiveLogService liveLogService) {
        this.liveLogService = liveLogService;
    }
    
    /**
     * Live logs dashboard
     */
    @GetMapping("/logs")
    public String logs() {
        return "logs";
    }
    
    /**
     * Get recent logs as HTML
     */
    @GetMapping("/api/logs")
    @ResponseBody
    public String getRecentLogs() {
        String logs = liveLogService.getLogsAsHtml();
        return logs.isEmpty() ? "No logs available yet. Start using the proxy to see activity." : logs;
    }
    
    /**
     * Get statistics as JSON
     */
    @GetMapping("/api/stats")
    @ResponseBody
    public LiveLogService.Statistics getStatistics() {
        return liveLogService.getStatistics();
    }
    
    /**
     * Server-Sent Events for real-time log streaming
     */
    @GetMapping("/api/logs/stream")
    public SseEmitter streamLogs() {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        
        // Add listener for new log entries
        LiveLogService.LogListener listener = entry -> {
            try {
                emitter.send("data:" + entry.toHtml() + "\n\n");
            } catch (Exception e) {
                // Client disconnected
            }
        };
        
        liveLogService.addListener(listener);
        
        // Send initial connection message
        executor.execute(() -> {
            try {
                emitter.send("data:🚀 Connected to Anti-Phishing AI Gateway logs\n\n");
                
                // Send recent logs
                for (LiveLogService.LogEntry entry : liveLogService.getRecentLogs(20)) {
                    emitter.send("data:" + entry.toHtml() + "\n\n");
                }
                
            } catch (Exception e) {
                liveLogService.removeListener(listener);
                emitter.completeWithError(e);
            }
        });
        
        // Clean up listener when connection closes
        emitter.onCompletion(() -> liveLogService.removeListener(listener));
        emitter.onError(throwable -> liveLogService.removeListener(listener));
        
        return emitter;
    }
}