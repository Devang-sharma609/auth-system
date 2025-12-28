package com.devang.auth_server.models;

import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class Users {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private UUID id;
    
    @Column(unique = true, nullable = false)
    private String username;

    private String pass_hash;
    
    @ColumnDefault("true")
    private boolean enabled;

    @CreationTimestamp
    private LocalDateTime created_at;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Roles role;
}
