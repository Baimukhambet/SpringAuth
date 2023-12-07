package com.albinachoi.endterm.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
// import org.apache.el.lang.FunctionMapperImpl.Function;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.boot.autoconfigure.ssl.SslBundleProperties.Key;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String SECRET_KEY = "4e0cc79f9e278f713573a6614958491a9b1c8f261c98ab3555bdf817eb473bd4";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey()) // Signing(secret) key is used to create a signature part of JWT to verity that the sender of JWT is who it claims to be and that the message was not changed along the way 
            .build()
            .parseClaimsJws(token)
            .getBody();    
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails); // Generate token without extra claims
    }

    public String generateToken(
        Map<String, Object> extraClaims,
        UserDetails userDetails
    ) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // to check if token is STILL valid
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 1000 * 24 * 3)) // The token is Valid for 3 days
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // return Token
    }

    public boolean isValidToken(String token, UserDetails userDetails) { // Check if token belongs to a User
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
