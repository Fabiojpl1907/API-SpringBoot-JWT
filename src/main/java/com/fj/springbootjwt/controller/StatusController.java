package com.fj.springbootjwt.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    // se a aplicação estiver no ar
    // aparece a mensagem quando entra na URL
    @RequestMapping("/status")
    public String viewStatus(){
        return "On Line";
    }
}
