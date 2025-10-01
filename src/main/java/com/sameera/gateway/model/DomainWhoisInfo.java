package com.sameera.gateway.model;

import java.util.Date;

public class DomainWhoisInfo {
    private String domain;
    private String registrar;
    private String registrant;
    private Date creationDate;
    private Date expirationDate;
    private Date updatedDate;
    private String nameServers;
    private String domainStatus;
    private boolean privacyProtected;
    private long domainAgeDays;
    private String registrantEmail;
    private String registrantCountry;
    private int whoisScore;

    // Getters and setters
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public String getRegistrar() { return registrar; }
    public void setRegistrar(String registrar) { this.registrar = registrar; }
    public String getRegistrant() { return registrant; }
    public void setRegistrant(String registrant) { this.registrant = registrant; }
    public Date getCreationDate() { return creationDate; }
    public void setCreationDate(Date creationDate) { this.creationDate = creationDate; }
    public Date getExpirationDate() { return expirationDate; }
    public void setExpirationDate(Date expirationDate) { this.expirationDate = expirationDate; }
    public Date getUpdatedDate() { return updatedDate; }
    public void setUpdatedDate(Date updatedDate) { this.updatedDate = updatedDate; }
    public String getNameServers() { return nameServers; }
    public void setNameServers(String nameServers) { this.nameServers = nameServers; }
    public String getDomainStatus() { return domainStatus; }
    public void setDomainStatus(String domainStatus) { this.domainStatus = domainStatus; }
    public boolean isPrivacyProtected() { return privacyProtected; }
    public void setPrivacyProtected(boolean privacyProtected) { this.privacyProtected = privacyProtected; }
    public long getDomainAgeDays() { return domainAgeDays; }
    public void setDomainAgeDays(long domainAgeDays) { this.domainAgeDays = domainAgeDays; }
    public String getRegistrantEmail() { return registrantEmail; }
    public void setRegistrantEmail(String registrantEmail) { this.registrantEmail = registrantEmail; }
    public String getRegistrantCountry() { return registrantCountry; }
    public void setRegistrantCountry(String registrantCountry) { this.registrantCountry = registrantCountry; }
    public int getWhoisScore() { return whoisScore; }
    public void setWhoisScore(int whoisScore) { this.whoisScore = whoisScore; }
}
