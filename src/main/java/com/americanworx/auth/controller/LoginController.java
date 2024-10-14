//package com.americanworx.auth.controller;
//
//
//
////import com.americanworx.auth.config.jwt.JwtProvider;
//import com.americanworx.auth.domain.AuthResponse;
//import com.americanworx.auth.domain.UserDtls;
//import com.americanworx.auth.service.UserService;
//import com.fasterxml.jackson.core.JsonProcessingException;
//import com.fasterxml.jackson.databind.ObjectMapper;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//import org.springframework.beans.factory.annotation.Autowired;
//
//import org.springframework.http.HttpStatus;
////import org.springframework.http.MediaType;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContext;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
//import org.springframework.security.web.context.SecurityContextRepository;
//
//import org.springframework.web.bind.annotation.*;
//
//
//@RestController
////@CrossOrigin(origins = "http://192.168.1.76:8090/")
//public class LoginController {
//
//    @Autowired
//    private AuthenticationManager authenticationManager;
//
//
//
//    @Autowired
//    private UserService userService;
//    private final SecurityContextRepository securityContextRepository =
//            new HttpSessionSecurityContextRepository();
//
////    public LoginController(AuthenticationManager authenticationManager) {
////        this.authenticationManager = authenticationManager;
////    }
//
////    @PostMapping(value = "/login")
////    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) throws JsonProcessingException {
////
////        System.out.println("--------------------------- " + loginRequest.toString());
////        Authentication authenticationRequest =
////                UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(), loginRequest.password());
////        System.out.println("------------------------1 " + authenticationRequest.toString());
////        Authentication authenticationResponse =
////                this.authenticationManager.authenticate(authenticationRequest);
////        System.out.println("--------------------------- " + authenticationResponse.toString());
////        SecurityContext context = SecurityContextHolder.createEmptyContext();
////        context.setAuthentication(authenticationResponse);
////        SecurityContextHolder.setContext(context);
////        System.out.println("---------------9 " + authenticationResponse.toString());
////        securityContextRepository.saveContext(context, request, response);
////
////
////        String token1 = JwtProvider.generateToken(authenticationResponse);
////        AuthResponse authResponse = new AuthResponse();
////        authResponse.setAuthenticationResponse(authenticationResponse);
////        authResponse.setJwt(token1);
////        authResponse.setMessage("Login success");
////
////        authResponse.setStatus(true);
////
////
////        return new ResponseEntity<>(authResponse, HttpStatus.OK);
////    }
//
//
//    public record LoginRequest(String username, String password) {
//    }
//
//    @PostMapping("/saveUser")
//    public ResponseEntity<?> saveUser(@RequestBody UserDtls user){
//        Boolean existsEmail = userService.existsEmail(user.getEmail());
//        if (existsEmail) {
//            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
//        } else {
//            UserDtls saveUser = userService.saveUser(user);
//            return ResponseEntity.status(HttpStatus.CREATED).body(saveUser);
//        }
//
//
//    }
//
//
//}
