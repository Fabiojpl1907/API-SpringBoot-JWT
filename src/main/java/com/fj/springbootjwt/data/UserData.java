package com.fj.springbootjwt.data;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;

@Getter @Setter @NoArgsConstructor
public class UserData implements Serializable {

    String userName;
    String password;
}
