package com.eternivity.auth.repository;

import com.eternivity.auth.entity.OAuthAccount;
import com.eternivity.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuthAccountRepository extends JpaRepository<OAuthAccount, Long> {

    /**
     * Find OAuth account by provider and provider user ID
     */
    Optional<OAuthAccount> findByProviderAndProviderUserId(String provider, String providerUserId);

    /**
     * Check if OAuth account exists for provider and provider user ID
     */
    boolean existsByProviderAndProviderUserId(String provider, String providerUserId);

    /**
     * Find OAuth account by user and provider
     */
    Optional<OAuthAccount> findByUserAndProvider(User user, String provider);

    /**
     * Check if user has OAuth account for provider
     */
    boolean existsByUser_UserIdAndProvider(UUID userId, String provider);
}
