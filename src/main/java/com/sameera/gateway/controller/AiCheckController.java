package com.sameera.gateway.controller;

import com.sameera.gateway.model.ProxyResponse;
import com.sameera.gateway.service.ProxyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class AiCheckController {
    @Autowired
    private ProxyService proxyService;

    @PostMapping("/ai-check")
    public Map<String, String> check(@RequestBody Map<String, String> body) {
        String url = body.get("url");
        if (url == null) {
            return Map.of("decision", "ALLOW");
        }
        // Run your phishing/cert/WHOIS logic here
        ProxyResponse proxyResponse = proxyService.processRequest(url, null);
        String decision = proxyResponse.getDecision().getAction().toString();
        return Map.of("decision", decision);
    }
}
