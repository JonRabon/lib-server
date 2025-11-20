package com.coderepojon.dbPostgres.domain.entities;

import jakarta.persistence.*;
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
@Entity
@Table(name = "user_profiles")
public class UserProfileEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private UserEntity user;

    @Column(nullable = false)
    private String email;

    private String firstName;
    private String lastName;
    private String middleName;

    @Column(name = "birthdate")
    private LocalDate birthdate;

    private String gender;
    private String maritalStatus;

    private String phoneNumber;
    private String alternatePhoneNumber;

    private String addressLine1;
    private String addressLine2;
    private String city;
    private String state;
    private String postalCode;
    private String country;

    private String avatarUrl;
    @Column(columnDefinition = "TEXT")
    private String bio;

    private String nationality;

    private Instant createdAt;
    private Instant updatedAt;
}
