package com.eternivity.auth.exception;

/**
 * Exception thrown when a token (reset/refresh/etc.) is invalid or expired.
 */
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
