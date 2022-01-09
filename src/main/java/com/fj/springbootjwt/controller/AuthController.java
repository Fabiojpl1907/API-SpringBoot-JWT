package com.fj.springbootjwt.controller;

import com.fj.springbootjwt.data.UserData;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    // pegar o login e encriptar
    // não é necessário instanciar pois criamos um Bean na classe main
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // criar o construto do encriptador
    public AuthController(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // criar método do tipo POST em / login

    @PostMapping("/login")
    // recebo de UserData -  quem faz a requisção passa esta informação
    public void login(@RequestBody UserData user) {
        // a senha é fornecida em texto plano e precisa ser encriptada
        // para que isto ocorra é necessário criar as classe que
        // façam a encriptação e a validação da senha
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    }

}
