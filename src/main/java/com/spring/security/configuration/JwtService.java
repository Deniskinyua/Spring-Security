package com.spring.security.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;

//15
@Service
public class JwtService {
    //17. Create teh secret key
    private static final String SECRET_KEY = "7e8e6646a06c29a00d927c15cb383436621fee34825c7305e52b48ea7b1aa6ee";

    public String extractUsername(String jwtToken) {

        return null;
    }
    //16. CReating claims
    private Claims extractAllClaims(String jwtToken){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws("jwtToken")
                .getBody();
    }

    private Key getSigningKey() {
        byte [] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
