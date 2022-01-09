package com.fj.springbootjwt.controller;

//import com.fj.springbootjwt.data.UserData;
//import com.fj.springbootjwt.service.UserDetailsServiceImpl;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RestController;
import java.util.List;

import com.fj.springbootjwt.data.UserData;
import com.fj.springbootjwt.service.UserDetailsServiceImpl;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class UserController {

    private final UserDetailsServiceImpl userDetailsService;

    public UserController(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @RequestMapping("/all-users")
    public List<UserData> listAllUsers() {
        return userDetailsService.ListUsers();
    }

}