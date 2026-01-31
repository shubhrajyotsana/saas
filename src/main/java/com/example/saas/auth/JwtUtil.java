package com.example.saas.auth;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    // For demo only — use env variable later
    private static final String SECRET =
            "qwerfderfedrtyuhyjiokl9876ghyvft";

    private static final long EXPIRATION_MS = 24 * 60 * 60 * 1000; // 24 hours

    private final SecretKey key = Keys.hmacShaKeyFor(
            SECRET.getBytes(StandardCharsets.UTF_8)
    );

    public String generateToken(Long userId, Long organizationId, String role) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .claim("orgId", organizationId)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims validateAndExtractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
