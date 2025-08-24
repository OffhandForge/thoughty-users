package com.biezbardis.thoughtyusers.utils;

import com.biezbardis.thoughtyusers.exceptions.KeyGenerationException;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class JwtUtils {

    private static final String jwtSigningPublicKey = """
            -----BEGIN PUBLIC KEY-----
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            ***REMOVED***
            -----END PUBLIC KEY-----""";

    public static Date getExpiration(String jwt) {
        return Jwts.parser()
                .verifyWith(getPublicKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload()
                .getExpiration();
    }

    static PublicKey getPublicKey() {
        String key = jwtSigningPublicKey.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new KeyGenerationException("Failed to generate public key", e);
        }
    }

}
