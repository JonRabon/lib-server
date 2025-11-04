package com.coderepojon.dbPostgres.services.impl;

import com.coderepojon.dbPostgres.controllers.ForceLogoutController;
import com.coderepojon.dbPostgres.domain.dto.TokenMetadata;
import com.coderepojon.dbPostgres.domain.entities.TokenEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenMetadataEntity;
import com.coderepojon.dbPostgres.domain.entities.TokenType;
import com.coderepojon.dbPostgres.domain.entities.UserEntity;
import com.coderepojon.dbPostgres.repositories.TokenMetadataRepository;
import com.coderepojon.dbPostgres.repositories.TokenRepository;
import com.coderepojon.dbPostgres.repositories.UserRepository;
import com.coderepojon.dbPostgres.services.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepo;
    private final TokenMetadataRepository metadataRepo;
    private final UserRepository userRepo; // admin revocation
    private final IpInfoService ipInfoService;

    @Value("${app.issuer:unknown-issuer}")
    private String issuer;

    // -------------------------------
    // Existence / Validity Check
    // -------------------------------
    @Override
    public boolean existAndValid(String token, UserEntity user) {
        return tokenRepo.findByTokenAndUser(token, user)
                .filter(t -> !t.isRevoked() && t.getExpiresAt().isAfter(Instant.now()))
                .isPresent();
    }

    // -------------------------------
    // Save Token (Basic)
    // -------------------------------
    @Override
    public void saveUserToken(UserEntity user, String jwtToken, TokenType type, Instant expiresAt) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status("ACTIVE")
                .build();

        tokenRepo.save(token);
    }

    // -------------------------------
    // Save Token (with status + metadata)
    // -------------------------------
    @Override
    public void saveUserTokenWithMetadata(
            UserEntity user,
            String jwtToken,
            TokenType type,
            Instant expiresAt,
            String status,
            TokenMetadata metadata,
            HttpServletRequest request
    ) {
        TokenEntity token = TokenEntity.builder()
                .user(user)
                .token(jwtToken)
                .type(type)
                .revoked(false)
                .expiresAt(expiresAt)
                .createdAt(Instant.now())
                .status(status != null ? status : "SUCCESS")
                .sessionId(metadata != null ? metadata.getSessionId() : null)
                .build();

        // server-side IP (trust server request)
        String ip = request != null ? extractClientIp(request) : null;
        IpInfoService.IpDetails ipDetails = ip != null ? ipInfoService.lookup(ip) : null;

        if (metadata != null) {
            // determine is_new_device
            Boolean isNewDevice = null;
            if (metadata.getDeviceId() != null) {
                List<TokenMetadataEntity> prev = metadataRepo.findAllByDeviceIdAndUserId(metadata.getDeviceId(), user.getId());
                isNewDevice = prev == null || prev.isEmpty();
            }

            // compute riskScore (simple heuristic)
            float score =0f;
            if (ipDetails != null && Boolean.TRUE.equals(ipDetails.proxy())) score += 60;
            if (Boolean.TRUE.equals(isNewDevice)) score += 25;

            // add small penalty if country mismatch with last known (optional)
            // cap
            score = Math.min(100f, score);

            // log.info("region: {}", ipDetails.region());
            TokenMetadataEntity metadataEntity = TokenMetadataEntity.builder()
                    .token(token)
                    .createdAt(Instant.now())
                    .deviceId(metadata != null ? metadata.getDeviceId() : null)
                    .device(metadata != null ? metadata.getDevice() : null)
                    .browser(metadata != null ? metadata.getBrowser() : null)
                    .os(metadata != null ? metadata.getOs() : null)
                    .ipAddress(ip != null ? ip : (metadata != null ? metadata.getIpAddress() : null))
                    .country(ipDetails != null && ipDetails.country_name() != null ? ipDetails.country_name() : (metadata != null ? metadata.getCountry() : null))
                    .city(ipDetails != null && ipDetails.city() != null ? ipDetails.city() : (metadata != null ? metadata.getCity() : null))
                    .sessionId(metadata != null ? metadata.getSessionId() : null)
                    .userAgentRaw(metadata != null ? metadata.getUserAgentRaw() : null)
                    .loginMethod(metadata != null ? metadata.getLoginMethod() : null)
                    .mfaUsed(Boolean.TRUE.equals(metadata.getMfaUsed()))
                    .mfaType(metadata != null ? metadata.getMfaType() : null)
                    .clientId(metadata != null ? metadata.getClientId() : null)
                    .isNewDevice(isNewDevice)
                    .isVpnOrProxy(ipDetails != null ? ipDetails.proxy() : null)
                    .issuer(issuer + "-" + (metadata.getIssuer() != null ? metadata.getIssuer() : "unknown"))
                    .networkProvider(ipDetails != null && ipDetails.org() != null ? ipDetails.org() : metadata.getNetworkProvider())
                    .latitude(ipDetails != null && ipDetails.latitude() != null ? ipDetails.latitude() : metadata.getLatitude())
                    .longitude(ipDetails != null && ipDetails.longitude() != null ? ipDetails.longitude() : metadata.getLongitude())
                    .timezone(ipDetails != null && ipDetails.timezone() != null ? ipDetails.timezone() : metadata.getTimezone())
                    .riskScore(score)
                    .success(Boolean.TRUE)
                    .build();

            token.setMetadata(metadataEntity);
        }
        // Persist both
        // Cascade takes care of metadata
        tokenRepo.save(token);
    }

    private String extractClientIp(HttpServletRequest request) {
        //Gives real client IP behind proxies
        //Can be spoofed if not coming from trusted proxies
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            return xff.split(",")[0].trim();
        }
        //Simple, always works
        //Can be wrong if behind proxies
        return request.getRemoteAddr();
    }

    // -------------------------------
    // Revoke Tokens
    // -------------------------------
    @Override
    public  void revokeAllUserTokens(UserEntity user) {
        List<TokenEntity> validToken = tokenRepo.findAllValidTokensByUser(user.getId());
        validToken.forEach(token -> token.setRevoked(true));
        tokenRepo.saveAll(validToken);
    }

    // --- Revoke all tokens for a user except a session ---
    @Override
    public void revokeAllExceptSession(UserEntity user, String keepSessionId) {
        List<TokenEntity> tokens = tokenRepo.findAllValidTokensByUser(user.getId());
        tokens.stream()
                .filter(t -> !Objects.equals(t.getSessionId(), keepSessionId))
                .forEach(t -> t.setRevoked(true));
        tokenRepo.saveAll(tokens);
    }

    @Override
    public boolean isTokenRevoked(String token) {
        return tokenRepo.findByToken(token)
                .map(TokenEntity::isRevoked)
                .orElse(true);// Treat missing tokens as revoke
    }

    @Override
    public void revokeToken(String token) {
        tokenRepo.findByToken(token).ifPresent(t -> {
            t.setRevoked(true);
            tokenRepo.save(t);
        });
    }

    @Override
    public void revokeTokensByUsername(String username) {
        userRepo.findByUsername(username).ifPresent(user -> {
            revokeAllUserTokens(user);
            user.setSession(null);
            userRepo.save(user);
        });

        // Notify via SSE
        ForceLogoutController.sendLogoutEventToAllSession(username);
    }

    // --- Revoke all tokens in a session ---
    @Override
    public void revokeTokensBySession(UserEntity user, String sessionId) {
        List<TokenEntity> tokens = tokenRepo.findAllByUserAndSessionId(user, sessionId);
        tokens.forEach(t -> {
            t.setRevoked(true);
            t.getMetadata().setLogoutAt(Instant.now());
        });
        tokenRepo.saveAll(tokens);
    }

    // Check if session is still valid
    public boolean isSessionActive(UserEntity user, String sessionId) {
        return tokenRepo.findAllByUserAndSessionId(user, sessionId).size() > 0;
    }
}
