package com.eternivity.auth.repository;

import com.eternivity.auth.entity.OAuthAccount;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuthAccountRepository extends JpaRepository<OAuthAccount, Long> {
}
