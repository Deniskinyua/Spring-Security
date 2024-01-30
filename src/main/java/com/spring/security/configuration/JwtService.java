package com.spring.security.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//15
@Service
public class JwtService {
    //17. Create teh secret key
    private static final String SECRET_KEY = "7e8e6646a06c29a00d927c15cb383436621fee34825c7305e52b48ea7b1aa6ee";

    public String extractUsername(String jwtToken) {

        //19.
        return extractClaim(jwtToken, Claims::getSubject);
    }
    //18. Method to extract a single claim passed:
    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(jwtToken);
        return claimResolver.apply(claims);
    }

    //21. Method to create token without extra claims/ from user details
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    //20. Method to generate a token
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
    }

    //22. Validating the token
    public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        final String username = extractUsername(jwtToken);
        return (username.equals(userDetails.getUsername())) && !isTokenExpires(jwtToken);
    }

    private boolean isTokenExpires(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    //16. Creating claims
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
