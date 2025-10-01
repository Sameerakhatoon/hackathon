package com.sameera.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.annotation.PostConstruct;

/**
 * Anti-Phishing AI Gateway Main Application
 * 
 * This application serves as an AI-powered proxy gateway that:
 * - Intercepts web traffic
 * - Detects phishing using Meta Llama via Cerebras API
 * - Scores SSL certificates for trust
 * - Makes intelligent blocking decisions
 * 
 * Sponsor Technologies Used:
 * - Meta: Llama LLM for phishing detection
 * - Cerebras: API hosting for Llama models
 * - Docker Compose: Containerization
 * 
 * @author Sameera Khatoon
 */
@SpringBootApplication
public class AntiPhishingGatewayApplication {
    
    private static final Logger logger = LoggerFactory.getLogger(AntiPhishingGatewayApplication.class);
    
    public static void main(String[] args) {
        logger.info("🛡️  Starting Anti-Phishing AI Gateway...");
        logger.info("📡 Using Meta Llama via Cerebras API for phishing detection");
        logger.info("🐳 Containerized with Docker Compose");
        
        SpringApplication.run(AntiPhishingGatewayApplication.class, args);
        
        logger.info("🚀 Anti-Phishing AI Gateway is now running!");
        logger.info("🌐 Configure your browser proxy to: http://localhost:8080");
    }
}