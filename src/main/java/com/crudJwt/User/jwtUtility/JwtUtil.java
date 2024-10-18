package com.crudJwt.User.jwtUtility;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {
    private static final String SECRET_KEY = "your_secret_key";

    // Extract username from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract expiration date from token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract any specific claim from token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    // Check if token is expired
    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Generate an access token
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", "ACCESS_TOKEN");  // Mark as access token
        return createToken(claims, username, 1000 * 60 * 1); // 5 min
    }

    // Generate a refresh token
    public String generateRefreshToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tokenType", "REFRESH_TOKEN");  // Mark as refresh token
        return createToken(claims, username, 1000 * 60 * 5); // 30 min
    }

    // Create the token
    private String createToken(Map<String, Object> claims, String username, long expirationTime) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    // Validate token based on token type
    public Boolean validateToken(String token, String username, String expectedTokenType) {
        final String extractedUsername = extractUsername(token);
        final String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
        return (extractedUsername.equals(username) && !isTokenExpired(token) && expectedTokenType.equals(tokenType));
    }
}
