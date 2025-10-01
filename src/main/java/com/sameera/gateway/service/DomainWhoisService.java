package com.sameera.gateway.service;

import org.apache.commons.net.whois.WhoisClient;

import com.sameera.gateway.model.DomainWhoisInfo;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DomainWhoisService {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DomainWhoisService.class);
    public DomainWhoisInfo getWhoisInfo(String domain) {
        logger.info("\uD83C\uDF10 [START] WHOIS lookup for domain: {}", domain);
        DomainWhoisInfo info = new DomainWhoisInfo();
        try {
            WhoisClient whois = new WhoisClient();
            String whoisServer = getWhoisServer(domain);
            logger.debug("\uD83C\uDF10 Connecting to WHOIS server: {}", whoisServer);
            whois.connect(whoisServer);
            String whoisData = whois.query(domain);
            whois.disconnect();
            // logger.info("\uD83C\uDF10 Raw WHOIS data for {}: {}", domain, whoisData);

            info.setDomain(domain);
            info.setRegistrar(extractField(whoisData, "Registrar:", "Registrar Name:"));
            info.setRegistrant(extractField(whoisData, "Registrant Name:", "Registrant Organization:"));
            info.setCreationDate(extractDate(whoisData, "Creation Date:"));
            info.setExpirationDate(extractDate(whoisData, "Registry Expiry Date:"));
            info.setUpdatedDate(extractDate(whoisData, "Updated Date:"));
            info.setNameServers(extractNameServers(whoisData));
            info.setDomainStatus(extractField(whoisData, "Domain Status:", null));
            info.setPrivacyProtected(whoisData.contains("Redacted for Privacy") || whoisData.contains("WhoisGuard"));
            info.setDomainAgeDays(calculateDomainAgeDays(info.getCreationDate()));
            info.setRegistrantEmail(extractField(whoisData, "Registrant Email:", "Registrant Contact Email:"));
            info.setRegistrantCountry(extractField(whoisData, "Registrant Country:", "Country:"));
            int score = scoreWhoisInfo(domain, info, whoisData);
            info.setWhoisScore(score);
            logger.info("\uD83C\uDF10 [END] WHOIS info for {}: age={} days, privacyProtected={}, whoisScore={}", domain, info.getDomainAgeDays(), info.isPrivacyProtected(), score);
        } catch (Exception e) {
            logger.error("\u274c Error during WHOIS lookup for {}: {}", domain, e);
        }
        return info;
    }

    private String getWhoisServer(String domain) {
        if (domain.endsWith(".com") || domain.endsWith(".net")) {
            return "whois.verisign-grs.com";
        } else if (domain.endsWith(".org")) {
            return "whois.pir.org";
        } else if (domain.endsWith(".info")) {
            return "whois.afilias.net";
        } else if (domain.endsWith(".biz")) {
            return "whois.neulevel.biz";
        } else if (domain.endsWith(".us")) {
            return "whois.nic.us";
        } else {
            return "whois.iana.org"; // fallback
        }
    }

    private String extractField(String data, String... keys) {
        for (String key : keys) {
            Pattern pattern = Pattern.compile(key + "\\s*(.*)");
            Matcher matcher = pattern.matcher(data);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
        }
        return "";
    }

    private Date extractDate(String data, String key) {
        // More comprehensive patterns for WHOIS date extraction
        String[] patterns = {
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)", // 1995-08-14T04:00:00Z (ISO 8601 with Z)
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z)", // 2023-01-15T10:30:00.000Z
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})", // 2023-01-15T10:30:00
            key + "\\s*(\\d{4}-\\d{2}-\\d{2})",                    // 2023-01-15
            key + "\\s*(\\d{2}-\\d{2}-\\d{4})",                    // 15-01-2023
            key + "\\s*(\\d{2}/\\d{2}/\\d{4})",                    // 15/01/2023
            key + "\\s*(\\d{4}/\\d{2}/\\d{2})",                    // 2023/01/15
            key + "\\s*(\\w{3}\\s+\\d{2},?\\s+\\d{4})",           // Jan 15, 2023
            key + "\\s*(\\d{2}\\s+\\w{3}\\s+\\d{4})",             // 15 Jan 2023
            key + "\\s*(\\d{2}\\s+\\w{3}\\s+\\d{4}\\s+\\d{2}:\\d{2}:\\d{2})", // 15 Jan 2023 10:30:00
            key + "\\s*(\\w{3}\\s+\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\d{4})", // Jan 15 10:30:00 2023
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})", // 2023-01-15 10:30:00
            key + "\\s*(\\d{2}\\.\\d{2}\\.\\d{4})",               // 15.01.2023
            key + "\\s*(\\d{4}\\.\\d{2}\\.\\d{2})",               // 2023.01.15
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\+\\d{2}:\\d{2})", // 2023-01-15T10:30:00+00:00
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\+\\d{2}:\\d{2})", // 2023-01-15T10:30:00.000+00:00
            key + "\\s*(\\d{2}-\\w{3}-\\d{4})",                   // 15-Jan-2023
            key + "\\s*(\\w{3}-\\d{2}-\\d{4})",                   // Jan-15-2023
            key + "\\s*(\\d{4}-\\w{3}-\\d{2})",                   // 2023-Jan-15
            key + "\\s*(\\d{2}\\s+\\w{3}\\s+\\d{4}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\w{3})", // 15 Jan 2023 10:30:00 UTC
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\w{3})", // 2023-01-15 10:30:00 UTC
            key + "\\s*(\\d{4}-\\d{2}-\\d{2})",                    // 2023-01-15
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})", // 2023-01-15T10:30:00
            key + "\\s*(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)" // 2023-01-15T10:30:00Z
        };
        
        String[] formats = {
            "yyyy-MM-dd'T'HH:mm:ss'Z'",           // 1995-08-14T04:00:00Z (ISO 8601 with Z)
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",       // 2023-01-15T10:30:00.000Z
            "yyyy-MM-dd'T'HH:mm:ss",              // 2023-01-15T10:30:00
            "yyyy-MM-dd",                         // 2023-01-15
            "dd-MM-yyyy", 
            "dd/MM/yyyy",
            "yyyy/MM/dd",
            "MMM dd, yyyy",
            "dd MMM yyyy",
            "dd MMM yyyy HH:mm:ss",
            "MMM dd HH:mm:ss yyyy",
            "yyyy-MM-dd HH:mm:ss",
            "dd.MM.yyyy",
            "yyyy.MM.dd",
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
            "dd-MMM-yyyy",
            "MMM-dd-yyyy",
            "yyyy-MMM-dd",
            "dd MMM yyyy HH:mm:ss z",
            "yyyy-MM-dd HH:mm:ss z",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd",
            "yyyy-MM-dd'T'HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
        };
        
        for (int i = 0; i < patterns.length; i++) {
            Pattern pattern = Pattern.compile(patterns[i], Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(data);
            if (matcher.find()) {
                try {
                    String dateStr = matcher.group(1).trim();
                    // Clean up common WHOIS date issues
                    dateStr = dateStr.replaceAll("\\s+", " "); // Normalize whitespace
                    dateStr = dateStr.replaceAll("\\s*UTC\\s*", " UTC"); // Normalize UTC
                    return new SimpleDateFormat(formats[i]).parse(dateStr);
                } catch (ParseException e) {
                    logger.debug("Failed to parse date '{}' with format '{}': {}", matcher.group(1), formats[i], e.getMessage());
                }
            }
        }
        
        // Try alternative key patterns
        String[] altKeys = {
            key.replace(":", ""),  // Remove colon
            key.replace("Date", ""), // Remove "Date" suffix
            key.replace(" ", ""),  // Remove spaces
            "created", "creation", "registered", "expires", "expiry", "updated", "modified",
            "Creation Date", "Registry Expiry Date", "Updated Date", "Domain Name Commencement Date",
            "Domain Expiration Date", "Last Updated", "Last Modified", "Registration Date"
        };
        
        for (String altKey : altKeys) {
            if (!altKey.equals(key)) {
                for (int i = 0; i < patterns.length; i++) {
                    String altPattern = patterns[i].replace(key, altKey);
                    Pattern pattern = Pattern.compile(altPattern, Pattern.CASE_INSENSITIVE);
                    Matcher matcher = pattern.matcher(data);
                    if (matcher.find()) {
                        try {
                            String dateStr = matcher.group(1).trim();
                            dateStr = dateStr.replaceAll("\\s+", " ");
                            dateStr = dateStr.replaceAll("\\s*UTC\\s*", " UTC");
                            return new SimpleDateFormat(formats[i]).parse(dateStr);
                        } catch (ParseException e) {
                            logger.debug("Failed to parse date '{}' with format '{}': {}", matcher.group(1), formats[i], e.getMessage());
                        }
                    }
                }
            }
        }
        
        // Try to find any date-like pattern in the WHOIS data as a last resort
        Pattern anyDatePattern = Pattern.compile("(\\d{4}-\\d{2}-\\d{2})", Pattern.CASE_INSENSITIVE);
        Matcher anyDateMatcher = anyDatePattern.matcher(data);
        if (anyDateMatcher.find()) {
            try {
                String dateStr = anyDateMatcher.group(1).trim();
                return new SimpleDateFormat("yyyy-MM-dd").parse(dateStr);
            } catch (ParseException e) {
                logger.debug("Failed to parse fallback date '{}': {}", anyDateMatcher.group(1), e.getMessage());
            }
        }
        
        logger.info("Could not extract date for key '{}' from WHOIS data", key);
        return null;
    }

    private String extractNameServers(String data) {
        Pattern pattern = Pattern.compile("Name Server:\\s*(\\S+)");
        Matcher matcher = pattern.matcher(data);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            sb.append(matcher.group(1)).append(", ");
        }
        return sb.length() > 0 ? sb.substring(0, sb.length() - 2) : "";
    }

    private long calculateDomainAgeDays(Date creationDate) {
        if (creationDate == null) {
            logger.warn("Creation date is null, cannot calculate domain age");
            return 0; // Return 0 instead of -1 for better scoring
        }
        
        long diffMillis = new Date().getTime() - creationDate.getTime();
        long ageDays = diffMillis / (1000 * 60 * 60 * 24);
        
        // Handle edge cases
        if (ageDays < 0) {
            logger.warn("Negative domain age calculated: {} days (creation date: {})", ageDays, creationDate);
            return 0; // Future creation date - treat as new domain
        }
        
        if (ageDays > 36500) { // More than 100 years
            logger.warn("Unusually old domain age: {} days (creation date: {})", ageDays, creationDate);
            return 36500; // Cap at 100 years
        }
        
        return ageDays;
    }

    // WHOIS scoring logic
    private int scoreWhoisInfo(String domain, DomainWhoisInfo info, String whoisData) {
        int score = 100;
        // 1. Domain age
        if (info.getDomainAgeDays() < 7) score -= 30;
        else if (info.getDomainAgeDays() < 30) score -= 20;
        else if (info.getDomainAgeDays() < 180) score -= 10;
        // 2. Registrar reputation
        String registrar = info.getRegistrar() != null ? info.getRegistrar().toLowerCase() : "";
        String[] reputableRegistrars = {"namecheap", "godaddy", "google", "enom", "gandi", "tucows"};
        boolean reputable = false;
        for (String rep : reputableRegistrars) {
            if (registrar.contains(rep)) { reputable = true; break; }
        }
        if (!reputable) score -= 15;
        // 3. Expiry date
        if (info.getExpirationDate() != null) {
            long daysToExpire = (info.getExpirationDate().getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24);
            if (daysToExpire < 30) score -= 20;
            else if (daysToExpire < 90) score -= 10;
        }
        // 4. Privacy protection
        if (info.isPrivacyProtected()) score -= 10;
        // 5. Registrant country (example: high risk countries)
        String country = info.getRegistrantCountry() != null ? info.getRegistrantCountry().toLowerCase() : "";
        String[] highRiskCountries = {"ru", "cn", "kp", "ir", "sy", "pk", "ng"};
        for (String risk : highRiskCountries) {
            if (country.equals(risk)) { score -= 15; break; }
        }
        // 6. Free email provider as registrant
        String email = info.getRegistrantEmail() != null ? info.getRegistrantEmail().toLowerCase() : "";
        String[] freeEmails = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"};
        for (String free : freeEmails) {
            if (email.endsWith(free)) { score -= 10; break; }
        }
        // 7. Typosquatting (simple check against popular brands)
        String[] brands = {"google", "facebook", "apple", "amazon", "microsoft", "paypal", "bank"};
        for (String brand : brands) {
            if (levenshtein(domain.toLowerCase(), brand) <= 2 && !domain.toLowerCase().contains(brand)) {
                score -= 25; break;
            }
        }
        // Clamp score
        if (score < 5) score = 5;
        if (score > 100) score = 100;
        return score;
    }
    // Levenshtein distance for typosquatting
    private int levenshtein(String a, String b) {
        int[] costs = new int[b.length() + 1];
        for (int j = 0; j < costs.length; j++) costs[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            costs[0] = i;
            int nw = i - 1;
            for (int j = 1; j <= b.length(); j++) {
                int cj = Math.min(1 + Math.min(costs[j], costs[j - 1]), a.charAt(i - 1) == b.charAt(j - 1) ? nw : nw + 1);
                nw = costs[j];
                costs[j] = cj;
            }
        }
        return costs[b.length()];
    }
}
