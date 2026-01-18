package com.eternivity.auth.repository;

import com.eternivity.auth.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    /**
     * Find a valid (unused and not expired) token by its hash
     */
    @Query("SELECT p FROM PasswordResetToken p WHERE p.tokenHash = :tokenHash AND p.usedAt IS NULL AND p.expiresAt > :now")
    Optional<PasswordResetToken> findValidTokenByHash(@Param("tokenHash") String tokenHash, @Param("now") LocalDateTime now);

    /**
     * Find token by hash regardless of validity
     */
    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /**
     * Invalidate all existing tokens for a user (mark as used)
     */
    @Modifying
    @Query("UPDATE PasswordResetToken p SET p.usedAt = :now WHERE p.userId = :userId AND p.usedAt IS NULL")
    void invalidateAllTokensForUser(@Param("userId") String userId, @Param("now") LocalDateTime now);

    /**
     * Delete expired tokens (cleanup job)
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken p WHERE p.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
}

