package com.coderepojon.dbPostgres.domain.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class CreateUserRequestDto {
    @NotBlank @Email
    private String email;

    // User Profile table
    @NotBlank
    private String firstName;
    private String middleName;
    @NotBlank
    private String lastName;

    @NotNull
    private LocalDate birthdate;
    private String gender;
    private String maritalStatus;
    private String nationality;

    @NotBlank
    private String phoneNumber;
    private String alternatePhoneNumber;

    @NotBlank
    private String addressLine1;
    private String addressLine2;
    @NotBlank
    private String city;
    @NotBlank
    private String state;
    @NotBlank
    private String postalCode;
    @NotBlank
    private String country;

    private String avatarUrl;
    private String bio;

    private Instant createdAt;
    private Instant updatedAt;
}
