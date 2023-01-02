package com.example.springsecurity.dto;

import lombok.Getter;

@Getter
public class SignupRequest {
    private String username;
    private String password;
    private boolean admin = false;
    private String adminToken = "";
}
