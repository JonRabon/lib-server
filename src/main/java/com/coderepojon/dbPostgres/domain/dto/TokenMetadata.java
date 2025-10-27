package com.coderepojon.dbPostgres.domain.dto;

import lombok.*;

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
}
