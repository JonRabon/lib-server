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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/sse")
public class ForceLogoutController {

    //Keep track of active SSE connections
    private static final Map<String, SseEmitter> emitters = new ConcurrentHashMap<>();
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    public ForceLogoutController(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping(value = "/subscribe/{username}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@PathVariable String username, @RequestParam("token") String token) {
        try {
            // Validate token manually
            String extractedUsername  = jwtUtil.extractUsername(token);
            if (!username.equals(extractedUsername )) {
                throw new RuntimeException("Username mismatch in token");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(extractedUsername );
            // Validate token
            if (!jwtUtil.isTokenValid(token, userDetails)) {
                throw new RuntimeException("Invalid or expired token");
            }

            // Valid user — register SSE emitter
            SseEmitter emitter = new SseEmitter(Long.MAX_VALUE); // Keep open
            emitters.put(username, emitter);

            emitter.onCompletion(() -> emitters.remove(username));
            emitter.onTimeout(() -> emitters.remove(username));

            System.out.println("SSE connected for user: " + username);
            return emitter;
        } catch (Exception e) {
            System.err.println("SSE subscription rejected: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid or expired token");
        }
    }

    // Called when an admin revokes someone's session
    public static void sendLogoutEvent(String username) {
        SseEmitter emitter = emitters.get(username);
        if (emitter != null) {
            try {
                System.out.println("Sending logout event to: " + username);
                emitter.send(SseEmitter.event().name("logout").data("Your session was revoked"));
                emitter.complete();
                emitters.remove(username);
            } catch (IOException e) {
                emitter.completeWithError(e);
                emitters.remove(username);
            }
        } else {
            System.out.println("No active SSE connection found for user: " + username);
        }
    }
}
