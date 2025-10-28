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
@Table(name = "token_metadata")
public class TokenMetadataEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "token_id", referencedColumnName = "id")
    private TokenEntity token;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    private String ipAddress;
    private String browser;
    private String os;
    private String device;
    private String deviceId;
    private String city;
    private String country;

    @Column(name = "user_agent_raw", columnDefinition = "TEXT")
    private String userAgentRaw;
    private String loginMethod;
    private Boolean mfaUsed;
    private String mfaType;
    private Boolean success;

    private String failureReason;
    private Double latitude;
    private Double longitude;
    private String timezone;
    private String sessionId;
    private String issuer;
    private String clientId;
    private Float riskScore;
    private Boolean isNewDevice;
    private Boolean isVpnOrProxy;
    private String networkProvider;
    private Instant logoutAt;

    private String revokedReason;
}
