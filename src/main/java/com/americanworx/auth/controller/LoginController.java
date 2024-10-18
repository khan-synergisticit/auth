package com.americanworx.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;


@RestController
public class LoginController {



    public record LoginRequest(String username, String password) {
    }

    @GetMapping("/getPrinciple")
    public ResponseEntity<?> getPrinciple() {
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        System.out.println("principal " + principal.getName());
        return new ResponseEntity<>(principal, HttpStatus.OK);

    }


}
