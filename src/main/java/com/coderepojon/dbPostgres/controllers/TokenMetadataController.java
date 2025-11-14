package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenMetadataEntity;
import com.coderepojon.dbPostgres.repositories.TokenMetadataRepository;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/tokens")
@CrossOrigin(origins = "http://localhost:4200")
@RequiredArgsConstructor
public class TokenMetadataController {

    private final TokenMetadataRepository metadataRepo;
    private final TokenRepository tokenRepo;
    private final UserRepository userRepo;

    // Return all token metadata (admin-only in real setup)
    @GetMapping("/metadata")
    public List<TokenMetadataResponse> getAllMetadata() {
        return metadataRepo.findAll().stream()
                .map(TokenMetadataResponse::fromEntity)
                .collect(Collectors.toList());
    }

    @GetMapping("/metadata/{username}")
    public List<TokenMetadataResponse> getUserMetadata(@PathVariable String username) {
        var user = userRepo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<TokenEntity> userTokens = tokenRepo.findAllValidTokensByUser(user.getId());
        return userTokens.stream()
                .map(TokenEntity::getMetadata)
                .filter(meta -> meta != null)
                .map(TokenMetadataResponse::fromEntity)
                .collect(Collectors.toList());
    }

    // ✅ DTO response (flattened structure)
    public static record TokenMetadataResponse(
            Long id,
            String username,
            String sessionId,
            String ipAddress,
            String city,
            String country,
            Instant createdAt,
            Double latitude,
            Double longitude,
            Instant logoutAt,
            String browser,
            String os,
            String device,
            Boolean isNewDevice,
            Boolean mfaUsed,
            String mfaType,
            String networkProvider,
            Boolean isVpnOrProxy,
            Float riskScore,
            Boolean success,
            String loginMethod,
            String issuer,
            String clientId,
            String revokedReason,
            Boolean revoked,
            Enum tokenType,
            String timezone
    ) {
        public static TokenMetadataResponse fromEntity(TokenMetadataEntity e) {
            return new TokenMetadataResponse(
                    e.getId(),
                    e.getToken() != null && e.getToken().getUser() != null ? e.getToken().getUser().getUsername() : null,
                    e.getSessionId(),
                    e.getIpAddress(),
                    e.getCity(),
                    e.getCountry(),
                    e.getCreatedAt(),
                    e.getLatitude(),
                    e.getLongitude(),
                    e.getLogoutAt(),
                    e.getBrowser(),
                    e.getOs(),
                    e.getDevice(),
                    e.getIsNewDevice(),
                    e.getMfaUsed(),
                    e.getMfaType(),
                    e.getNetworkProvider(),
                    e.getIsVpnOrProxy(),
                    e.getRiskScore(),
                    e.getSuccess(),
                    e.getLoginMethod(),
                    e.getIssuer(),
                    e.getClientId(),
                    e.getRevokedReason(),
                    e.getToken() != null && e.getToken().getUser() != null ? e.getToken().isRevoked() : null,
                    e.getToken() != null && e.getToken().getUser() != null ? e.getToken().getType() : null,
                    e.getTimezone()
            );
        }

    }

}
