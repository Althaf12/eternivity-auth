package com.eternivity.auth.service;

import com.eternivity.auth.entity.User;
import com.eternivity.auth.entity.UserSubscription;
import com.eternivity.auth.repository.UserSubscriptionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

/**
 * Service for managing user subscriptions.
 * Handles default subscription assignment for new and existing users.
 */
@Service
public class UserSubscriptionService {

    private static final Logger logger = LoggerFactory.getLogger(UserSubscriptionService.class);

    // Service codes for available applications
    public static final String SERVICE_CODE_EXPENSE_TRACKER = "ExpenseTracker";
    public static final String SERVICE_CODE_PASSWORD_VAULT = "PasswordVault";

    // Default plan and status for free subscriptions
    public static final String PLAN_FREE = "free";
    public static final String STATUS_ACTIVE = "Active";

    // End date for free plans (effectively unlimited)
    public static final LocalDate FREE_PLAN_END_DATE = LocalDate.of(3000, 1, 1);

    // List of all available service codes for default subscription assignment
    private static final List<String> ALL_SERVICE_CODES = List.of(
            SERVICE_CODE_EXPENSE_TRACKER,
            SERVICE_CODE_PASSWORD_VAULT
            // Add more service codes here as new applications are added
    );

    private final UserSubscriptionRepository userSubscriptionRepository;

    public UserSubscriptionService(UserSubscriptionRepository userSubscriptionRepository) {
        this.userSubscriptionRepository = userSubscriptionRepository;
    }

    /**
     * Assigns default free subscriptions to a new user for all available services.
     *
     * @param user The newly registered user
     */
    @Transactional
    public void assignDefaultSubscriptions(User user) {
        logger.info("Assigning default subscriptions for new user: {}", user.getUserId());

        LocalDate startDate = user.getCreatedAt() != null
                ? user.getCreatedAt().toLocalDate()
                : LocalDate.now();

        for (String serviceCode : ALL_SERVICE_CODES) {
            createFreeSubscription(user, serviceCode, startDate);
        }

        logger.info("Assigned {} default subscription(s) to user: {}",
                ALL_SERVICE_CODES.size(), user.getUserId());
    }

    /**
     * Ensures a user has default subscriptions for all available services.
     * Creates missing subscriptions for existing users who may not have them.
     *
     * @param user The user to check and assign subscriptions to
     * @return The list of subscriptions (existing + newly created)
     */
    @Transactional
    public List<UserSubscription> ensureDefaultSubscriptions(User user) {
        List<UserSubscription> existingSubscriptions =
                userSubscriptionRepository.findByUser_UserId(user.getUserId());

        LocalDate startDate = user.getCreatedAt() != null
                ? user.getCreatedAt().toLocalDate()
                : LocalDate.now();

        // Check for missing service subscriptions
        for (String serviceCode : ALL_SERVICE_CODES) {
            boolean hasSubscription = existingSubscriptions.stream()
                    .anyMatch(sub -> serviceCode.equals(sub.getServiceCode()));

            if (!hasSubscription) {
                logger.info("Creating missing default subscription for user {} - service: {}",
                        user.getUserId(), serviceCode);
                UserSubscription newSub = createFreeSubscription(user, serviceCode, startDate);
                existingSubscriptions.add(newSub);
            }
        }

        return existingSubscriptions;
    }

    /**
     * Gets all subscriptions for a user, ensuring default subscriptions exist.
     *
     * @param userId The user's ID
     * @param user The user entity (required for creating missing subscriptions)
     * @return List of user subscriptions
     */
    @Transactional
    public List<UserSubscription> getSubscriptionsWithDefaults(UUID userId, User user) {
        return ensureDefaultSubscriptions(user);
    }

    /**
     * Creates a free subscription for a specific service.
     *
     * @param user The user to create the subscription for
     * @param serviceCode The service code
     * @param startDate The subscription start date
     * @return The created subscription
     */
    private UserSubscription createFreeSubscription(User user, String serviceCode, LocalDate startDate) {
        UserSubscription subscription = new UserSubscription();
        subscription.setUser(user);
        subscription.setServiceCode(serviceCode);
        subscription.setPlan(PLAN_FREE);
        subscription.setStatus(STATUS_ACTIVE);
        subscription.setStartDate(startDate);
        subscription.setEndDate(FREE_PLAN_END_DATE);

        UserSubscription saved = userSubscriptionRepository.save(subscription);
        logger.info("Created subscription id={} for user {} service {}", saved.getId(), user.getUserId(), serviceCode);
        return saved;
    }

    /**
     * Checks if a user has an active subscription for a specific service.
     *
     * @param userId The user's ID
     * @param serviceCode The service code to check
     * @return true if the user has an active subscription
     */
    @Transactional(readOnly = true)
    public boolean hasActiveSubscription(UUID userId, String serviceCode) {
        return userSubscriptionRepository.existsByUserIdAndServiceCodeAndStatus(
                userId, serviceCode, STATUS_ACTIVE);
    }

    /**
     * Gets a user's subscription for a specific service.
     *
     * @param userId The user's ID
     * @param serviceCode The service code
     * @return The subscription, or null if not found
     */
    @Transactional(readOnly = true)
    public UserSubscription getSubscription(UUID userId, String serviceCode) {
        return userSubscriptionRepository.findByUserIdAndServiceCode(userId, serviceCode)
                .orElse(null);
    }
}

