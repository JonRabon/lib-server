package com.coderepojon.dbPostgres.domain.dto;

import lombok.Data;

import java.util.Map;

@Data
public class RefreshRequestDTO {
    private String refreshToken;
    private String accessToken;
    private Map<String, Object> metadata;
}
