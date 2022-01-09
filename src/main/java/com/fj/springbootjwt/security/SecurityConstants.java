package com.fj.springbootjwt.security;

public class SecurityConstants {
    // chave interna so vista na sua aplicação
    // sem ela não sera possivel decriptografa a senha
    // mesma senha / user em aplicações diferentes
    // gera criptografias diferentes
    public static final String SECRET = "SecretKeyToGenJWTs";

    // tempo de duração da chave , em milisegundos
    public static final long EXPIRATION_TIME = 864_000_000; // 10 days

    // prefixo que indentifica o tipo de token sendo criado
    public static final String TOKEN_PREFIX = "Bearer ";

    // cabeçalho onde estará o token
    public static final String HEADER_STRING = "Authorization";

    // url onde para entrar não sera solicitada senha
    public static final String SIGN_UP_URL = "/login";
    public static final String STATUS_URL = "/status";

}
