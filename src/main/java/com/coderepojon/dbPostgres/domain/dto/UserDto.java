package com.coderepojon.dbPostgres.domain.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserDto {

    private String username;
    private String password;

    @NotBlank
    private String status; // "activate", "deactivate", "suspend", "block"
}
