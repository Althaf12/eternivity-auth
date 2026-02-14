package com.eternivity.auth.exception;

/**
 * Exception thrown for MFA-related errors.
 */
public class MfaException extends RuntimeException {

    public MfaException(String message) {
        super(message);
    }

    public MfaException(String message, Throwable cause) {
        super(message, cause);
    }
}

