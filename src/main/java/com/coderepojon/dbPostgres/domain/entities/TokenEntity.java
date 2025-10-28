package com.coderepojon.dbPostgres.domain.entities;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "tokens")
public class TokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private UserEntity user;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType type; // ACCESS / REFRESH

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(length = 20)
    private String status; // SUCCESS / REVOKED / FAILED

    @Column(name = "session_id", length = 100)
    private String sessionId; // tie multiple tokens to same session

    @OneToOne(mappedBy = "token", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private TokenMetadataEntity metadata;
}
