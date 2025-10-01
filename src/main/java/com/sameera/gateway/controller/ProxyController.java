package com.sameera.gateway.controller;

import com.sameera.gateway.model.ProxyResponse;
import com.sameera.gateway.model.SecurityAction;
import com.sameera.gateway.service.ProxyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import okhttp3.Headers;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import okhttp3.HttpUrl;

@Controller
@RequestMapping("/proxy")
public class ProxyController {
    private static final Logger logger = LoggerFactory.getLogger(ProxyController.class);

    @Autowired
    private ProxyService proxyService;

    @GetMapping("/**")
    public Object handleGetRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestParam(value = "url", required = false) String url) {
        if (url == null) {
            return ResponseEntity.badRequest().body("Missing 'url' parameter");
        }
        return processRequest(url, "GET", request, response);
    }

    @PostMapping("/**")
    public Object handlePostRequest(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestParam(value = "url", required = false) String url) {
        if (url == null) {
            return ResponseEntity.badRequest().body("Missing 'url' parameter");
        }
        return processRequest(url, "POST", request, response);
    }

    private Object processRequest(String targetUrl, String method,
                                 HttpServletRequest request,
                                 HttpServletResponse response) {
        logger.info("🌐 Proxy request: {} {}", method, targetUrl);
        try {
            // Extract headers
            Headers.Builder headersBuilder = new Headers.Builder();
            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                String headerValue = request.getHeader(headerName);
                if (headerValue != null) {
                    headersBuilder.add(headerName, headerValue);
                }
            }
            Headers headers = headersBuilder.build();

            // Process through AI pipeline
            ProxyResponse proxyResponse = proxyService.processRequest(targetUrl, headers);

            switch (proxyResponse.getDecision().getAction()) {
                case BLOCK:
                    return handleBlockedRequest(proxyResponse);
                case WARN:
                    return handleWarningRequest(proxyResponse, targetUrl, method, headers);
                case ALLOW:
                    return handleAllowedRequest(targetUrl, method, headers);
                default:
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body("Unknown security decision");
            }
        } catch (Exception e) {
            logger.error("❌ Error processing proxy request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Proxy error: " + e.getMessage());
        }
    }

    private ModelAndView handleBlockedRequest(ProxyResponse proxyResponse) {
        ModelAndView mav = new ModelAndView("block");
        mav.setStatus(HttpStatus.FORBIDDEN);
        mav.addObject("url", proxyResponse.getTargetUrl());
        mav.addObject("reason", proxyResponse.getDecision().getReason());
        mav.addObject("aiAnalysis", proxyResponse.getDecision().getLlamaExplanation() != null ? proxyResponse.getDecision().getLlamaExplanation() : "This site matches phishing patterns and is blocked for your safety.");
        return mav;
    }

    private ModelAndView handleWarningRequest(ProxyResponse proxyResponse, String targetUrl, String method, Headers headers) {
        ModelAndView mav = new ModelAndView("warn");
        mav.setStatus(HttpStatus.OK);
        mav.addObject("url", targetUrl);
        mav.addObject("reason", proxyResponse.getDecision().getReason());
        mav.addObject("aiAnalysis", proxyResponse.getDecision().getLlamaExplanation() != null ? proxyResponse.getDecision().getLlamaExplanation() : "Potential security concerns detected");
        return mav;
    }

    private void copyResponseHeaders(Response source, HttpServletResponse target) {
        for (String name : source.headers().names()) {
            for (String value : source.headers(name)) {
                // Exclude hop-by-hop headers
                if (!name.equalsIgnoreCase("Transfer-Encoding") && !name.equalsIgnoreCase("Content-Length")) {
                    target.addHeader(name, value);
                }
            }
        }
    }

    private Headers buildForwardHeaders(Headers original, String targetUrl) {
        Headers.Builder builder = new Headers.Builder();
        HttpUrl httpUrl = HttpUrl.parse(targetUrl);
        String originalHost = httpUrl != null ? httpUrl.host() : null;
        for (String name : original.names()) {
            if (name.equalsIgnoreCase("Host")) {
                if (originalHost != null) builder.add("Host", originalHost);
            } else if (!name.equalsIgnoreCase("Content-Length") && !name.equalsIgnoreCase("Transfer-Encoding")) {
                builder.add(name, original.get(name));
            }
        }
        // If Host header was not present, add it
        if (originalHost != null && builder.get("Host") == null) {
            builder.add("Host", originalHost);
        }
        return builder.build();
    }

    private Object handleAllowedRequest(String targetUrl, String method, Headers headers) {
        try {
            Headers forwardHeaders = buildForwardHeaders(headers, targetUrl);
            Response response = proxyService.forwardRequest(targetUrl, method, forwardHeaders, null);
            HttpServletResponse servletResponse = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
            if (servletResponse == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("No servlet response available");
            }
            servletResponse.setStatus(response.code());
            copyResponseHeaders(response, servletResponse);
            // Stream the response body
            try (InputStream in = response.body().byteStream(); OutputStream out = servletResponse.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }
                out.flush();
            }
            response.close();
            return null; // Response is fully handled
        } catch (IOException e) {
            logger.error("Error forwarding request to {}: {}", targetUrl, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("Error contacting destination: " + e.getMessage());
        }
    }
}
