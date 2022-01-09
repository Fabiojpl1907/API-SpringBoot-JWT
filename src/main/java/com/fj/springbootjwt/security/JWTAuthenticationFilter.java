package com.fj.springbootjwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fj.springbootjwt.data.UserData;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

// criando um filtro
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

// a requisição recebe o AuthenticationManager -------------------------------------
    // é do security do SpringBoot
    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
// -----------------------------------------------------------------------------

    // implementado métodos que vem da classe que extendemos
    // UsernamePasswordAuthenticationFilter
    // localizar o autenticador
    // UserData - dados do usuário que estará dentro do token
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            UserData creds = new ObjectMapper()
                    .readValue(req.getInputStream(), UserData.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            // pedir para autenticar
                            creds.getUserName(),
                            creds.getPassword(),
                            new ArrayList<>())
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // se a autenticar for bem sucedida
    // gera o token utilzando  Auth0
    // coloca no header do retorno da requisição
    // coloca no token :
    // os dados do usuário
    // ( poderia colcar qualquer coisa necessaria , por exemplo o saldo do correntista
    // o prozo de validade
    // qual algoritmo utilizado
    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        String token = JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()));

        res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
    }
}
