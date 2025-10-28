package com.coderepojon.dbPostgres.domain.dto;

import lombok.*;

import java.time.Instant;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenMetadata {
    private String deviceId;
    private String device;
    private String browser;
    private String os;
    private String ipAddress;
    private String country;
    private String city;
    private String sessionId;
    private String userAgentRaw;
    private String loginMethod;
    private Boolean mfaUsed;
    private String mfaType;
    private Boolean isNewDevice;
    private Boolean isVpnOrProxy;
    private String networkProvider;
    private Instant createdAt;
    private String issuer;
    private String clientId;
    private Double riskScore;
    private Boolean success;
    private String failureReason;
    private Double latitude;
    private Double longitude;
    private String timezone;
    private Instant logoutAt;
    private String revokedReason;
}
