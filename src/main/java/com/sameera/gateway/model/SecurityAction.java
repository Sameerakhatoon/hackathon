package com.sameera.gateway.model;

/**
 * Enum representing the action to take for a security decision
 */
public enum SecurityAction {
    ALLOW,    // Allow the request to proceed
    WARN,     // Allow but show warning to user
    BLOCK     // Block the request completely
}