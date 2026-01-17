package com.devang.auth_server.repos;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.devang.auth_server.models.RefreshTokens;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokens, UUID>{
    void deleteById(UUID id);
}
