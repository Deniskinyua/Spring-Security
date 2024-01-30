package com.spring.security.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
//10. Implemnting the FilterChain
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //14.
    private final JwtService jwtService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        //11. Implementing check for jwt token
        final String authorizationHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;

       //12.
        if(authorizationHeader == null ||! authorizationHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }
        //13.
        jwtToken = authorizationHeader.substring(7);
        userEmail = jwtService.extractUsername(jwtToken);//todo extract the userEmail from the JWT token;

    }
}
