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
public class WhitelistService {
    
    private static final Logger logger = LoggerFactory.getLogger(WhitelistService.class);
    
    // In-memory cache for fast lookups
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    
    // File path for persistence
    private static final String WHITELIST_FILE = "logs/whitelist.txt";
    
    @PostConstruct
    public void initializeWhitelist() {
        loadWhitelistFromFile();
        logger.info("✅ Whitelist service initialized with {} URLs", whitelist.size());
    }
    
    /**
     * Check if URL is in whitelist (fast lookup)
     */
    public boolean isWhitelisted(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.readLock().lock();
        try {
            // Normalize URL for consistent lookup
            String normalizedUrl = normalizeUrl(url);
            boolean whitelisted = whitelist.contains(normalizedUrl);
            
            if (whitelisted) {
                logger.info("✅ URL found in whitelist: {}", url);
            }
            
            return whitelisted;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Add URL to whitelist
     */
    public boolean addToWhitelist(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.writeLock().lock();
        try {
            String normalizedUrl = normalizeUrl(url);
            boolean added = whitelist.add(normalizedUrl);
            
            if (added) {
                logger.info("➕ Added URL to whitelist: {}", url);
                saveWhitelistToFile();
            }
            
            return added;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Remove URL from whitelist
     */
    public boolean removeFromWhitelist(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        lock.writeLock().lock();
        try {
            String normalizedUrl = normalizeUrl(url);
            boolean removed = whitelist.remove(normalizedUrl);
            
            if (removed) {
                logger.info("➖ Removed URL from whitelist: {}", url);
                saveWhitelistToFile();
            }
            
            return removed;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get all URLs in whitelist
     */
    public Set<String> getAllWhitelistedUrls() {
        lock.readLock().lock();
        try {
            return new HashSet<>(whitelist);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get whitelist size
     */
    public int getWhitelistSize() {
        lock.readLock().lock();
        try {
            return whitelist.size();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Clear entire whitelist
     */
    public void clearWhitelist() {
        lock.writeLock().lock();
        try {
            int size = whitelist.size();
            whitelist.clear();
            logger.info("🗑️ Cleared whitelist (removed {} URLs)", size);
            saveWhitelistToFile();
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
        
        // Remove www. prefix for domain-level whitelisting
        if (normalized.startsWith("www.")) {
            normalized = normalized.substring(4);
        }
        
        return normalized;
    }
    
    /**
     * Load whitelist from file
     */
    private void loadWhitelistFromFile() {
        Path filePath = Paths.get(WHITELIST_FILE);
        
        if (!Files.exists(filePath)) {
            logger.info("📄 Whitelist file does not exist, creating default whitelist");
            createDefaultWhitelistFile();
            return;
        }
        
        try (BufferedReader reader = Files.newBufferedReader(filePath)) {
            String line;
            int loaded = 0;
            
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    whitelist.add(line);
                    loaded++;
                }
            }
            
            logger.info("📄 Loaded {} URLs from whitelist file", loaded);
            
        } catch (IOException e) {
            logger.error("❌ Error loading whitelist from file: {}", e.getMessage());
        }
    }
    
    /**
     * Save whitelist to file
     */
    private void saveWhitelistToFile() {
        Path filePath = Paths.get(WHITELIST_FILE);
        
        try {
            // Create parent directories if they don't exist
            Files.createDirectories(filePath.getParent());
            
            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write("# Anti-Phishing Gateway Whitelist");
                writer.newLine();
                writer.write("# Format: one URL per line (without http/https)");
                writer.newLine();
                writer.write("# Generated: " + new Date());
                writer.newLine();
                writer.newLine();
                
                // Sort URLs for better readability
                List<String> sortedUrls = new ArrayList<>(whitelist);
                Collections.sort(sortedUrls);
                
                for (String url : sortedUrls) {
                    writer.write(url);
                    writer.newLine();
                }
            }
            
            logger.debug("💾 Saved {} URLs to whitelist file", whitelist.size());
            
        } catch (IOException e) {
            logger.error("❌ Error saving whitelist to file: {}", e.getMessage());
        }
    }
    
    /**
     * Create default whitelist file with trusted domains
     */
    private void createDefaultWhitelistFile() {
        Path filePath = Paths.get(WHITELIST_FILE);
        
        try {
            Files.createDirectories(filePath.getParent());
            
            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write("# Anti-Phishing Gateway Whitelist");
                writer.newLine();
                writer.write("# Format: one URL per line (without http/https)");
                writer.newLine();
                writer.write("# Generated: " + new Date());
                writer.newLine();
                writer.newLine();
                
                // Add default trusted domains
                String[] defaultDomains = {
                    "google.com",
                    "microsoft.com", 
                    "github.com",
                    "stackoverflow.com",
                    "wikipedia.org",
                    "amazon.com",
                    "apple.com",
                    "facebook.com",
                    "twitter.com",
                    "linkedin.com",
                    "youtube.com",
                    "netflix.com",
                    "spotify.com",
                    "paypal.com",
                    "ebay.com",
                    "reddit.com",
                    "instagram.com",
                    "whatsapp.com",
                    "telegram.org",
                    "discord.com",
                    "slack.com",
                    "zoom.us",
                    "dropbox.com",
                    "onedrive.live.com",
                    "office.com",
                    "outlook.com",
                    "gmail.com",
                    "yahoo.com",
                    "bing.com",
                    "duckduckgo.com",
                    "cloudflare.com",
                    "akamai.com",
                    "fastly.com",
                    "jsdelivr.net",
                    "cdnjs.cloudflare.com",
                    "fonts.googleapis.com",
                    "fonts.gstatic.com",
                    "ajax.googleapis.com",
                    "apis.google.com",
                    "accounts.google.com",
                    "myaccount.google.com",
                    "support.google.com",
                    "developers.google.com",
                    "console.cloud.google.com",
                    "azure.microsoft.com",
                    "portal.azure.com",
                    "docs.microsoft.com",
                    "support.microsoft.com",
                    "developer.microsoft.com",
                    "login.microsoftonline.com",
                    "outlook.office365.com",
                    "teams.microsoft.com",
                    "onedrive.com",
                    "skype.com",
                    "xbox.com",
                    "store.steampowered.com",
                    "steamcommunity.com",
                    "twitch.tv",
                    "vimeo.com",
                    "soundcloud.com",
                    "bandcamp.com",
                    "medium.com",
                    "dev.to",
                    "hashnode.com",
                    "codepen.io",
                    "jsfiddle.net",
                    "repl.it",
                    "github.io",
                    "gitlab.com",
                    "bitbucket.org",
                    "npmjs.com",
                    "pypi.org",
                    "maven.apache.org",
                    "gradle.org",
                    "docker.com",
                    "kubernetes.io",
                    "terraform.io",
                    "ansible.com",
                    "jenkins.io",
                    "travis-ci.com",
                    "circleci.com",
                    "github.com",
                    "gitlab.com",
                    "bitbucket.org",
                    "atlassian.com",
                    "jira.com",
                    "confluence.com",
                    "trello.com",
                    "asana.com",
                    "notion.so",
                    "airtable.com",
                    "zapier.com",
                    "ifttt.com",
                    "webhook.site",
                    "ngrok.com",
                    "postman.com",
                    "insomnia.rest",
                    "swagger.io",
                    "openapi.org",
                    "jsonplaceholder.typicode.com",
                    "httpbin.org",
                    "reqres.in",
                    "jsonapi.org",
                    "restcountries.eu",
                    "restcountries.com",
                    "api.github.com",
                    "api.twitter.com",
                    "api.spotify.com",
                    "api.unsplash.com",
                    "api.nasa.gov",
                    "api.openweathermap.org",
                    "api.exchangerate-api.com",
                    "api.coinbase.com",
                    "api.binance.com",
                    "api.kraken.com",
                    "api.coingecko.com",
                    "api.cryptocompare.com",
                    "api.blockchain.info",
                    "api.etherscan.io",
                    "api.bscscan.com",
                    "api.polygonscan.com",
                    "api.arbiscan.io",
                    "api.optimistic.etherscan.io",
                    "api.ftmscan.com",
                    "api.snowtrace.io",
                    "api.cronoscan.com",
                    "api.moonbeam.moonscan.io",
                    "api.moonriver.moonscan.io",
                    "api.aurorascan.dev",
                    "api.celoscan.xyz",
                    "api.harmony.one",
                    "api.avax.network",
                    "api.solana.com",
                    "api.algorand.com",
                    "api.tezos.com",
                    "api.cardano.org",
                    "api.polkadot.network",
                    "api.kusama.network",
                    "api.subscan.io",
                    "api.chainlink.network",
                    "api.uniswap.org",
                    "api.1inch.io",
                    "api.curve.fi",
                    "api.aave.com",
                    "api.compound.finance",
                    "api.yearn.finance",
                    "api.sushiswap.org",
                    "api.pancakeswap.finance",
                    "api.quickswap.exchange",
                    "api.spookyswap.finance",
                    "api.spiritswap.finance",
                    "api.beefy.finance",
                    "api.autofarm.network",
                    "api.pancakebunny.finance",
                    "api.venus.io",
                    "api.cream.finance",
                    "api.belt.fi",
                    "api.ellipsis.finance",
                    "api.alpaca.finance",
                    "api.valas.finance",
                    "api.iron.finance",
                    "api.tranchess.com",
                    "api.alpha.finance",
                    "api.badger.finance",
                    "api.harvest.finance",
                    "api.pickle.finance",
                    "api.yam.finance",
                    "api.synthetix.io",
                    "api.makerdao.com",
                    "api.instadapp.io",
                    "api.debank.com",
                    "api.zerion.io",
                    "api.1inch.exchange",
                    "api.paraswap.io",
                    "api.0x.org",
                    "api.kyber.network",
                    "api.bancor.network",
                    "api.balancer.exchange",
                    "api.mstable.org",
                    "api.renproject.io",
                    "api.keep.network",
                    "api.nucypher.com",
                    "api.threshold.network",
                    "api.tornado.cash",
                    "api.mixers.io",
                    "api.privacy.com",
                    "api.cash.app",
                    "api.venmo.com",
                    "api.zelle.com",
                    "api.paypal.com",
                    "api.stripe.com",
                    "api.square.com",
                    "api.shopify.com",
                    "api.woocommerce.com",
                    "api.magento.com",
                    "api.prestashop.com",
                    "api.opencart.com",
                    "api.bigcommerce.com",
                    "api.squarespace.com",
                    "api.wix.com",
                    "api.wordpress.com",
                    "api.blogger.com",
                    "api.tumblr.com",
                    "api.livejournal.com",
                    "api.medium.com",
                    "api.substack.com",
                    "api.ghost.org",
                    "api.jekyllrb.com",
                    "api.hugo.io",
                    "api.gatsbyjs.com",
                    "api.nextjs.org",
                    "api.nuxtjs.org",
                    "api.svelte.dev",
                    "api.vuejs.org",
                    "api.reactjs.org",
                    "api.angular.io",
                    "api.emberjs.com",
                    "api.backbonejs.org",
                    "api.jquery.com",
                    "api.lodash.com",
                    "api.underscorejs.org",
                    "api.momentjs.com",
                    "api.dayjs.com",
                    "api.date-fns.org",
                    "api.chartjs.org",
                    "api.d3js.org",
                    "api.plotly.com",
                    "api.highcharts.com",
                    "api.amcharts.com",
                    "api.fusioncharts.com",
                    "api.anychart.com",
                    "api.jsplumb.org",
                    "api.cytoscape.org",
                    "api.visjs.org",
                    "api.threejs.org",
                    "api.babylonjs.com",
                    "api.playcanvas.com",
                    "api.unity.com",
                    "api.unrealengine.com",
                    "api.godotengine.org",
                    "api.blender.org",
                    "api.autodesk.com",
                    "api.adobe.com",
                    "api.figma.com",
                    "api.sketch.com",
                    "api.invisionapp.com",
                    "api.marvelapp.com",
                    "api.proto.io",
                    "api.principle.com",
                    "api.framer.com",
                    "api.webflow.com",
                    "api.bubble.io",
                    "api.glideapps.com",
                    "api.adalo.com",
                    "api.thunkable.com",
                    "api.appgyver.com",
                    "api.mendix.com",
                    "api.outsystems.com",
                    "api.salesforce.com",
                    "api.hubspot.com",
                    "api.marketo.com",
                    "api.pardot.com",
                    "api.mailchimp.com",
                    "api.constantcontact.com",
                    "api.aweber.com",
                    "api.getresponse.com",
                    "api.activecampaign.com",
                    "api.drip.com",
                    "api.klaviyo.com",
                    "api.sendgrid.com",
                    "api.mailgun.com",
                    "api.postmarkapp.com",
                    "api.sendinblue.com",
                    "api.mandrill.com",
                    "api.sparkpost.com",
                    "api.elasticemail.com",
                    "api.pepipost.com",
                    "api.socketlabs.com",
                    "api.mailjet.com",
                    "api.twilio.com",
                    "api.nexmo.com",
                    "api.plivo.com",
                    "api.bandwidth.com",
                    "api.telnyx.com",
                    "api.signalwire.com",
                    "api.agora.io",
                    "api.tokbox.com",
                    "api.twilio.com",
                    "api.vonage.com",
                    "api.ringcentral.com",
                    "api.8x8.com",
                    "api.five9.com",
                    "api.nice.com",
                    "api.genesys.com",
                    "api.avaya.com",
                    "api.cisco.com",
                    "api.poly.com",
                    "api.logitech.com",
                    "api.jabra.com",
                    "api.sennheiser.com",
                    "api.bose.com",
                    "api.sony.com",
                    "api.samsung.com",
                    "api.lg.com",
                    "api.panasonic.com",
                    "api.philips.com",
                    "api.sharp.com",
                    "api.toshiba.com",
                    "api.hitachi.com",
                    "api.fujitsu.com",
                    "api.nec.com",
                    "api.lenovo.com",
                    "api.hp.com",
                    "api.dell.com",
                    "api.asus.com",
                    "api.msi.com",
                    "api.gigabyte.com",
                    "api.asrock.com",
                    "api.evga.com",
                    "api.corsair.com",
                    "api.thermaltake.com",
                    "api.coolermaster.com",
                    "api.nzxt.com",
                    "api.fractal-design.com",
                    "api.lian-li.com",
                    "api.antec.com",
                    "api.seasonic.com",
                    "api.corsair.com",
                    "api.evga.com",
                    "api.bequiet.com",
                    "api.silverstone.com",
                    "api.bitfenix.com",
                    "api.phanteks.com",
                    "api.inwin.com",
                    "api.rosewill.com",
                    "api.diypc.com",
                    "api.raidmax.com",
                    "api.xigmatek.com",
                    "api.deepcool.com",
                    "api.idcooling.com",
                    "api.arctic.com",
                    "api.noctua.com",
                    "api.coolermaster.com",
                    "api.corsair.com",
                    "api.thermaltake.com",
                    "api.nzxt.com",
                    "api.fractal-design.com",
                    "api.lian-li.com",
                    "api.antec.com",
                    "api.seasonic.com",
                    "api.bequiet.com",
                    "api.silverstone.com",
                    "api.bitfenix.com",
                    "api.phanteks.com",
                    "api.inwin.com",
                    "api.rosewill.com",
                    "api.diypc.com",
                    "api.raidmax.com",
                    "api.xigmatek.com",
                    "api.deepcool.com",
                    "api.idcooling.com",
                    "api.arctic.com",
                    "api.noctua.com"
                };
                
                for (String domain : defaultDomains) {
                    writer.write(domain);
                    writer.newLine();
                }
            }
            
        } catch (IOException e) {
            logger.error("❌ Error creating default whitelist file: {}", e.getMessage());
        }
    }
}
