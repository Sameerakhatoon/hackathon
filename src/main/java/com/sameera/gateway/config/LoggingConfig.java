package com.sameera.gateway.config;

import com.sameera.gateway.service.LiveLogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.PostConstruct;

/**
 * Configuration to set up log interception
 */
@Configuration
public class LoggingConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(LoggingConfig.class);
    
    @Autowired
    private LiveLogService liveLogService;
    
    @PostConstruct
    public void init() {
        logger.info("🚀 Live logging system initialized");
        liveLogService.addLogEntry("INFO", "LoggingConfig", "🚀 Live logging system initialized", Thread.currentThread().getName());
    }
}