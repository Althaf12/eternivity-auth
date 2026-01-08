package com.eternivity.auth.repository;

import com.eternivity.auth.entity.UserSubscription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserSubscriptionRepository extends JpaRepository<UserSubscription, Long> {

    List<UserSubscription> findByUser_UserId(UUID userId);

    /**
     * Check if a user has an active subscription for a specific service.
     */
    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END FROM UserSubscription s " +
           "WHERE s.user.userId = :userId AND s.serviceCode = :serviceCode AND s.status = :status")
    boolean existsByUserIdAndServiceCodeAndStatus(
            @Param("userId") UUID userId,
            @Param("serviceCode") String serviceCode,
            @Param("status") String status);

    /**
     * Find a specific subscription for a user and service.
     */
    @Query("SELECT s FROM UserSubscription s WHERE s.user.userId = :userId AND s.serviceCode = :serviceCode")
    Optional<UserSubscription> findByUserIdAndServiceCode(
            @Param("userId") UUID userId,
            @Param("serviceCode") String serviceCode);

    /**
     * Check if a user has any subscription for a specific service.
     */
    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END FROM UserSubscription s " +
           "WHERE s.user.userId = :userId AND s.serviceCode = :serviceCode")
    boolean existsByUserIdAndServiceCode(
            @Param("userId") UUID userId,
            @Param("serviceCode") String serviceCode);
}
