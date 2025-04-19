package com.biezbardis.thoughtyusers.utils;

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
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9xXNdFhloPTRevXcFN9
            f5lVOZrnefC+5XOBZ/Do6mB84GV+UmShk7hbQDIcx3Lz+a4KiBr1uZ7/sUNmXspu
            7xqVI6Vdia/kQeLAAJLjLNo9sMeC3q3rxrn/Qn+HbCPuLMyPOlEizNJQTAMYaZkO
            mFj/D6+nqDcigVTtMigzPYEduutdwIgdKrcxtrpEvsM16J1zBRHdHztHlRXUD4Jp
            7kFQRPtKF3iIQOi9FSzpvTJQNtGlZa68/ep6dFEJEZS2+R9K8F+WA2IRgkJfLQrS
            kc2u0Anbll6T7EIFJFUEM+EiyS25/dtFIS+uNlWP7e/waHy0tJTb4W+x7OV5GPLo
            xwIDAQAB
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
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) { // TODO implement exception handler
            throw new RuntimeException(e);
        }
    }

}
