package com.biezbardis.thoughtyusers.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenProvider implements JwtService {
    protected static final int ACCESS_TOKEN_LIFE = 1000 * 60 * 15; // 15 min
    protected static final String CLAIM_SCOPES = "scopes";

    @Value("${token.issuer}")
    private String issuingAuthority;
    @Value("${token.audience}")
    private String workingAudience;
    @Value("${token.signing.privateKey}")
    private String jwtSigningPrivateKey;
    @Value("${token.signing.publicKey}")
    private String jwtSigningPublicKey;

    @NonNull
    private final EndpointCollector collector;

    @Override
    public Set<String> extractScopes(String token) {
        Object scopesObj = extractAllClaims(token).get("scopes");

        if (scopesObj instanceof Collection<?>) {
            return ((Collection<?>) scopesObj).stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }

        return Collections.emptySet();
    }

    @Override
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateAccessToken(UserDetails userDetails) {
        return Jwts.builder()
                .issuer(issuingAuthority)
                .subject(userDetails.getUsername())
                .audience().add(workingAudience).and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_LIFE))
                .claims(Map.of(CLAIM_SCOPES, collector.getEndpoints()))
                .signWith(getPrivateKey()).compact();

    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        boolean isUserValid = userName.equals(userDetails.getUsername());
        return isUserValid && isIssuerValid(token) && isAudienceValid(token) && !isTokenExpired(token);
    }

    private boolean isIssuerValid(String token) {
        return extractIssuer(token).equals(issuingAuthority);
    }

    private boolean isAudienceValid(String token) {
        return extractAudience(token).contains(workingAudience);
    }

    @Override
    public boolean isTokenExpired(String token) {
        Date exp;
        try {
            exp = extractExpiration(token);
        } catch (ExpiredJwtException e) {
            return true;
        }
        return exp.before(new Date(System.currentTimeMillis()));
    }

    private Set<String> extractAudience(String token) {
        return extractClaim(token, Claims::getAudience);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private String extractIssuer(String token) {
        return extractClaim(token, Claims::getIssuer);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Obtaining the signing private key for JWT token
     *
     * @return private key
     */
    PrivateKey getPrivateKey() {
        String key = jwtSigningPrivateKey.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        var spec = new PKCS8EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // TODO implement exception handler
            throw new RuntimeException(e);
        }
    }

    /**
     * Obtaining the signing public key for JWT token
     *
     * @return public key
     */
    PublicKey getPublicKey() {
        String key = jwtSigningPublicKey.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // TODO implement exception handler
            throw new RuntimeException(e);
        }
    }
}
