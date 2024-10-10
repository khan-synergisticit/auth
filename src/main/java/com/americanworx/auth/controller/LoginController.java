package com.americanworx.auth.controller;


import com.americanworx.auth.config.jwt.JwtProvider;
import com.americanworx.auth.domain.AuthResponse;
import com.americanworx.auth.domain.UserDtls;
import com.americanworx.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;



    @Autowired
    private UserService userService;
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

//    public LoginController(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        Authentication authenticationRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
        Authentication authenticationResponse =
                this.authenticationManager.authenticate(authenticationRequest);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authenticationResponse);
        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, request, response);
        String token = JwtProvider.generateToken(authenticationResponse);



        AuthResponse authResponse = new AuthResponse();
        authResponse.setAuthenticationResponse(authenticationResponse);
        authResponse.setMessage("Login success");
        authResponse.setJwt(token);
        authResponse.setStatus(true);

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.OK);
    }


    public record LoginRequest(String username, String password) {
    }

    @PostMapping("/saveUser")
    public ResponseEntity<?> saveUser(@ModelAttribute UserDtls user){

        Boolean existsEmail = userService.existsEmail(user.getEmail());

        if (existsEmail) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        } else {
            UserDtls saveUser = userService.saveUser(user);
            return ResponseEntity.status(HttpStatus.CREATED).body(saveUser);


        }


    }


}
