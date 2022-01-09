package com.fj.springbootjwt.service;

import com.fj.springbootjwt.data.UserData;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // por ser "final" precisa ser inicializado
    public UserDetailsServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserData user = findUser( username);
        if ( user == null ){
            throw new UsernameNotFoundException( username);
        }

        return new User( user.getUserName(), user.getPassword(), Collections.emptyList());
    }

    // este metodo poderia ser construido para ir buscar o usuário
    // em qualuer lugar ( banco de dados, arquivo texto , etc )
    private UserData findUser(String username) {

        UserData user = new UserData();
        user.setUserName("admin");
        user.setPassword( bCryptPasswordEncoder.encode("nimda"));

        return user;
    }


    public List<UserData> ListUsers() {
        ArrayList<UserData> lst = new ArrayList<>();
        lst.add(findUser("admin"));
        return lst;
    }

}
