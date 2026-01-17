package com.devang.auth_server.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.devang.auth_server.repos.UserRepository;

@Service
public class AuthenticationManager {
    
    @Autowired
    UserRepository userRepository;

    public boolean authenticate(String username, String password) {
        
        String pswdHash = new BCryptPasswordEncoder().encode(password);
        return userRepository.findByUsername(username).getPass_hash().equals(pswdHash);
    }
}
