package com.coderepojon.dbPostgres.domain.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class BulkStatusUpdateDto {
    @NotEmpty
    private List<Long> ids;

    @NotBlank
    private String status; // "activate", "deactivate", "suspend", "block"
}
