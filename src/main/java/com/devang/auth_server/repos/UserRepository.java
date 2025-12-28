package com.devang.auth_server.repos;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.devang.auth_server.models.RefreshTokens;
import com.devang.auth_server.models.Users;


@Repository
public interface UserRepository extends JpaRepository<Users, Long>{
	Users find(UUID id);
	Users findByUsername(String username);
	RefreshTokens findTokenByUserId(UUID userId);
}
