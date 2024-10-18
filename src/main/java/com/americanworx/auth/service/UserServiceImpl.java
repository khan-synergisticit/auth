package com.americanworx.auth.service;


import com.americanworx.auth.domain.UserDtls;
import com.americanworx.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;


    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDtls saveUser(UserDtls user) {
        passwordEncoder = new BCryptPasswordEncoder();
        if(user.getRole() == null) {
            user.setRole("ROLE_USER");
        }
        String encodePassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodePassword);
        UserDtls saveUser = userRepository.save(user);
        return saveUser;
    }

    @Override
    public UserDtls getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public List<UserDtls> getUsers(String role) {
        return userRepository.findByRole(role);
    }




    @Override
    public Boolean existsEmail(String email) {
        return userRepository.existsByEmail(email);
    }

}
