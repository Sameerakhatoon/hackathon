package com.sameera.gateway.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import com.sameera.gateway.service.LiveLogService;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * Custom logback appender that sends logs to LiveLogService
 */
public class LiveLogAppender extends AppenderBase<ILoggingEvent> implements ApplicationContextAware {
    
    private ApplicationContext applicationContext;
    private LiveLogService liveLogService;
    
    @Override
    protected void append(ILoggingEvent event) {
        if (liveLogService == null && applicationContext != null) {
            try {
                liveLogService = applicationContext.getBean(LiveLogService.class);
            } catch (Exception e) {
                // LiveLogService not available yet
                return;
            }
        }
        
        if (liveLogService != null) {
            liveLogService.addLogEntry(
                event.getLevel().toString(),
                event.getLoggerName(),
                event.getFormattedMessage(),
                event.getThreadName()
            );
        }
    }
    
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }
}