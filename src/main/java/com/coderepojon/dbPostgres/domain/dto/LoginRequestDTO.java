package com.coderepojon.dbPostgres.domain.dto;

import lombok.Data;

import java.util.Map;

@Data
public class LoginRequestDTO {
    private String username;
    private String password;
    private Map<String, Object> metadata;
}
