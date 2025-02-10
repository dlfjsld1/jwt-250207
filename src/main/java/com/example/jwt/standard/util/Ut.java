package com.example.jwt.standard.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
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
        public static String createToken(String keyString, int expireSeconds, Map<String, Object> claims) {

            SecretKey secretKey = Keys.hmacShaKeyFor(keyString.getBytes());

            Date issuedAt = new Date();
            Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);
            return Jwts.builder()
                    .claims(claims)
                    .issuedAt(issuedAt)
                    .expiration(expiration)
                    .signWith(secretKey)
                    .compact();

        }

        public static boolean isValidToken(String keyString, String token) {
            try {

                SecretKey secretKey = Keys.hmacShaKeyFor(keyString.getBytes());

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

        public static Map<String, Object> getPayload(String keyString, String jwtStr) {

            SecretKey secretKey = Keys.hmacShaKeyFor(keyString.getBytes());

            return (Map<String, Object>)Jwts
                    .parser()
                    .verifyWith(secretKey)
                    .build()
                    .parse(jwtStr)
                    .getPayload();
        }
    }
}

