package com.coderepojon.dbPostgres.domain.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserProfileDto {
    private Long id;
    private Long userId;

    @NotBlank
    @Email
    private String email;

    private String username;
    private String status;
    private Instant userUpdatedAt;
    private String session;

    @NotBlank
    private String firstName;

    private String middleName;

    @NotBlank
    private String lastName;

    private String fullName;

    @NotNull
    private LocalDate birthdate;

    private String gender;
    private String maritalStatus;

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
    private String nationality;

    private Instant createdAt;
    private Instant updatedAt;
}

