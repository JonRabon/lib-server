package com.coderepojon.dbPostgres.controllers;

import com.coderepojon.dbPostgres.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/sse")
public class ForceLogoutController {

    // Track multiple SSE emitters per username (multi-session support)
    // 🔹 Maps: username → list of sessionIds
    private static final Map<String, List<String>> userSessions = new ConcurrentHashMap<>();

    // 🔹 Maps: sessionId → SseEmitter
    private static final Map<String, SseEmitter> sessionEmitters = new ConcurrentHashMap<>();

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public ForceLogoutController(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Each browser or device connects with its own sessionId.
     * Token is still validated, but emitter is keyed by sessionId.
     */
    @GetMapping(value = "/subscribe/{username}/{sessionId}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@PathVariable String username, @PathVariable String sessionId, @RequestParam("token") String token) {
        try {
            // Validate token
            String extractedUsername = jwtUtil.extractUsername(token);
            if (!username.equals(extractedUsername)) {
                throw new RuntimeException("Username mismatch in token");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(extractedUsername);
            if (!jwtUtil.isTokenValid(token, userDetails)) {
                throw new RuntimeException("Invalid or expired token");
            }

            // Create and store SSE emitter
            SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
            sessionEmitters.put(sessionId, emitter);

            userSessions.computeIfAbsent(username, k -> new ArrayList<>()).add(sessionId);

            emitter.onCompletion(() -> removeEmitter(username, sessionId));
            emitter.onTimeout(() -> removeEmitter(username, sessionId));

            System.out.printf("SSE connected for user=%s, session=%s%n", username, sessionId);
            return emitter;

        } catch (Exception e) {
            System.err.printf("SSE subscription rejected for %s: %s%n", username, e.getMessage());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid or expired token");
        }
    }

    // Remove a specific emitter when closed or timed out
    public static void removeEmitter(String username, String sessionId) {
        sessionEmitters.remove(sessionId);
        userSessions.computeIfPresent(username, (key, sessions) -> {
            sessions.remove(sessionId);
            return sessions.isEmpty() ? null : sessions;
        });
        System.out.printf("SSE connection removed: user=%s, session=%s%n", username, sessionId);
    }

    // Called when an admin revokes someone's session
    public static void sendLogoutEventToAllSession(String username) {
        List<String> sessions = userSessions.get(username);
        if (sessions == null || sessions.isEmpty()) {
            System.out.printf("ℹNo active sessions for user=%s%n", username);
            return;
        }

        System.out.printf("Sending logout to all %d sessions for user=%s%n", sessions.size(), username);
        for (String sessionId : sessions) {
            sendLogoutEventToSession(sessionId);
        }

        // Clean up after logout
        userSessions.remove(username);
    }

    // Notify multiple sessions (e.g., admin revokes all of a user’s sessions).
    public static void sendLogoutEventToSessions(List<String> sessionIds) {
        for (String sessionId : sessionIds) {
            sendLogoutEventToSession(sessionId);
        }
    }

    // Force logout for one specific session
    public static void sendLogoutEventToSession(String sessionId) {
        SseEmitter emitter = sessionEmitters.get(sessionId);
        if (emitter != null) {
            try {
                System.out.printf("Sending logout event to sessionId=%s%n", sessionId);
                emitter.send(SseEmitter.event().name("logout").data("Your session has been revoked"));
                emitter.complete();
            } catch (IOException e) {
                emitter.completeWithError(e);
            } finally {
                sessionEmitters.remove(sessionId);
            }
        } else {
            System.out.printf("No active SSE connection for sessionId=%s%n", sessionId);
        }
    }
}
