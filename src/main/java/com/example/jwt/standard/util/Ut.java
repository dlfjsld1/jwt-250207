package com.example.jwt.standard.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.Map;

public class Ut {
    public static class Json {
        private static final ObjectMapper objectMapper = new ObjectMapper();
        public static String toString(Object obj) {
            try {
                return objectMapper.writeValueAsString(obj);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class Jwt {
        public static String createToken(Key secretKey, int expireSeconds, Map<String, Object> claims) {

            Date issuedAt = new Date();
            Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);
            return Jwts.builder()
                    .claims(claims)
                    .issuedAt(issuedAt)
                    .expiration(expiration)
                    .signWith(secretKey)
                    .compact();

        }

        public static boolean isValidToken(SecretKey secretKey, String token) {
            try {
                //parse 중 이상을 감지하면 오류가 뜸
                Jwts
                        .parser()
                        .verifyWith(secretKey)
                        .build()
                        .parse(token);
            } catch(Exception e) {
                return false;
            }

            return true;
        }
    }
}

