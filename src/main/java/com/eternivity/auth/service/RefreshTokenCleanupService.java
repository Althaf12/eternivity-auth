package com.eternivity.auth.service;

import com.eternivity.auth.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service for cleaning up expired and revoked refresh tokens.
 * This prevents the refresh_tokens table from growing indefinitely.
 */
@Service
public class RefreshTokenCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenCleanupService.class);

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenCleanupService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    /**
     * Clean up expired refresh tokens daily at 3 AM.
     * Expired tokens are no longer usable and can be safely deleted.
     */
    @Scheduled(cron = "${app.refresh-token.cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void cleanupExpiredTokens() {
        logger.info("Starting cleanup of expired refresh tokens");
        int deletedCount = refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
        logger.info("Deleted {} expired refresh tokens", deletedCount);
    }
}

