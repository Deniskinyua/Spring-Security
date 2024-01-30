package com.spring.security.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
//10. Implemnting the FilterChain

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    //14.
    private final JwtService jwtService;
    //24 and create a bean of type UserDetailsService
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) {

        //11. Implementing check for jwt token
        final String authenticationHeader = request.getHeader("Authorization");
        final String jwtToken;
        final String userEmail;

       //12.
        if (authenticationHeader == null || !authenticationHeader.startsWith("Bearer ")) {
            try {
                filterChain.doFilter(request, response);
            } catch (IOException e) {
                System.out.println("In Catch:  IOException");
                e.printStackTrace();
            } catch (ServletException e) {
                System.out.println("In Catch:  ServletException");
                e.printStackTrace();
            }

            return;
        }
        //13.
        jwtToken = authenticationHeader.substring(7);
        userEmail = jwtService.extractUsername(jwtToken);//todo extract the userEmail from the JWT token;
        //23.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        try {
            filterChain.doFilter(request, response);
        } catch (IOException e) {
            System.out.println("In Catch:  IOException");
            e.printStackTrace();
        } catch (ServletException e) {
            System.out.println("In Catch:  ServletException");
            e.printStackTrace();
        }
    }
}
