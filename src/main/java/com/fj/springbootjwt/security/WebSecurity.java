package com.fj.springbootjwt.security;

import com.fj.springbootjwt.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

    // declarando 2 serviços
    private final UserDetailsServiceImpl userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // criar construtor dos serviços
    public WebSecurity(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailsService = userDetailsService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // fazer a configuração
    // informar ao Spring qual segurança que quero na aplicação
    // desabilitado cors - posso chamar meu serviço de qualquer URL
    // cors força que as apis acessem todas as paginas somente que estejam dentro
    // da URL  principal (  www.minhapagina.com )
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
                // permitir  GET da STATUS_URL
                .antMatchers(HttpMethod.GET, SecurityConstants.STATUS_URL)
                .permitAll()
                // permitir POST da SIGN_UP_URL
                .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
                .permitAll()
                // qualuer outra requisição precisa estar autenticado
                .anyRequest().authenticated()
                .and()
                // filtro que faz a autenticação - gera o token
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                // filtro que faz a autorização - le o token
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // não precisa guardar a sessão
              .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    // encripta e desencripta a password
    // pega os detalhes do usuário passado pelo serviço
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

     // avisando de que qualquer url que fizer a requisição , vou aceitar
    // de qualquer servidor que vir a requisção da API será aceita
      @Bean
      CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
      }
}