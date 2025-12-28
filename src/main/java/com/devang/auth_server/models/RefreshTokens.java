package com.devang.auth_server.models;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.ColumnDefault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;

@Entity
public class RefreshTokens {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private UUID id;

    @OneToOne
    private Users user;

    @Column(unique = true)
    String token_hash;

    LocalDateTime expires_at;

    @ColumnDefault("false")
    boolean revoked;
}
