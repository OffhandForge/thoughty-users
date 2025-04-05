package com.biezbardis.thoughtyauth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

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
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {
    protected static final int ACCESS_TOKEN_LIFE = 1000 * 60 * 15; // 15 min
    protected static final int REFRESH_TOKEN_LIFE = 1000 * 60 * 60 * 24 * 7; // 1 week
    public static final String CLAIM_SCOPES = "scopes";

    @Value("${token.issuer}")
    private String issuingAuthority;
    @Value("${token.audience}")
    private String workingAudience;
    @Value("${token.signing.privateKey}")
    private String jwtSigningPrivateKey;
    @Value("${token.signing.publicKey}")
    private String jwtSigningPublicKey;

    private final RequestMappingHandlerMapping handlerMapping;

    /**
     * Extracting username from token
     *
     * @param token access token
     * @return username
     */
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Access token generation
     *
     * @param userDetails user data
     * @return access token
     */
    public String generateAccessToken(UserDetails userDetails) {
        return Jwts.builder()
                .issuer(issuingAuthority)
                .subject(userDetails.getUsername())
                .audience().add(workingAudience).and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_LIFE))
                .claims(Map.of(CLAIM_SCOPES, getAllEndpoints()))
                .signWith(getPrivateKey()).compact();

    }

    /**
     * Refresh token generation
     *
     * @param userDetails user data
     * @return access token
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return Jwts.builder()
                .issuer(issuingAuthority)
                .subject(userDetails.getUsername())
                .audience().add(workingAudience).and()
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_LIFE))
                .signWith(getPrivateKey()).compact();

    }

    /**
     * Access token validation check
     *
     * @param token       access token
     * @param userDetails user data
     * @return true, if token is valid
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        boolean isValidUser = userName.equals(userDetails.getUsername());
        final String issuer = extractIssuer(token);
        boolean isValidIssuer = issuer.equals(issuingAuthority);
        final Set<String> audience = extractAudience(token);
        boolean isValidAudience = audience.contains(workingAudience);
        final Set<String> scopes = extractScopes(token);
        boolean isValidScopes = scopes.containsAll(getAllEndpoints());
        return isValidUser && isValidIssuer && isValidAudience && isValidScopes && !isTokenExpired(token);
    }

    /**
     * Access token expiration check
     *
     * @param token access token
     * @return true, if token expired
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    /**
     * Extracting audience from the access token
     *
     * @param token access token
     * @return audience
     */
    private Set<String> extractAudience(String token) {
        return extractClaim(token, Claims::getAudience);
    }

    /**
     * Extracting issuer from the access token
     *
     * @param token access token
     * @return issuer
     */
    private String extractIssuer(String token) {
        return extractClaim(token, Claims::getIssuer);
    }

    /**
     * Extracting expiration date from the access token
     *
     * @param token access token
     * @return expiration date
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extracting scopes from the access token
     *
     * @param token access token
     * @return scopes
     */
    private Set<String> extractScopes(String token) {
        Object scopesObj = extractAllClaims(token).get("scopes");

        if (scopesObj instanceof Collection<?>) {
            return ((Collection<?>) scopesObj).stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }

        return Collections.emptySet();
    }

    /**
     * Extracting data from a token
     *
     * @param token           access token
     * @param claimsResolvers data extraction function
     * @param <T>             data type
     * @return data
     */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    /**
     * Extracting all data from the access token
     *
     * @param token access token
     * @return data
     */
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
    private PrivateKey getPrivateKey() {
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
    private PublicKey getPublicKey() {
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

    /**
     * Obtaining the set of API endpoints
     *
     * @return set of API endpoints
     */
    private Set<String> getAllEndpoints() {
        return handlerMapping.getHandlerMethods()
                .entrySet().stream()
                .flatMap(entry -> {
                    var mapping = entry.getKey();
                    var methods = mapping.getMethodsCondition().getMethods();
                    var condition = Objects.requireNonNull(mapping.getPatternsCondition());
                    var paths = condition.getPatterns();

                    Set<String> result = new HashSet<>();
                    for (var method : methods) {
                        for (var path : paths) {
                            result.add(method.name() + " " + path);
                        }
                    }
                    return result.stream();
                })
                .collect(Collectors.toSet());
    }
}
