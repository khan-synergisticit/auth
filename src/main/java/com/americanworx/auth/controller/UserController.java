package com.americanworx.auth.controller;

import com.americanworx.auth.domain.UserDtls;
import com.americanworx.auth.service.UserService;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired private UserService userService;

    @RequestMapping(value = "/save", method = RequestMethod.POST, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createUser(@RequestBody JsonNode node) {
        System.out.println("User: " + node.toString());
        UserDtls user = new UserDtls();
        user.setPassword(node.get("password").asText());
        user.setEmail(node.get("email").asText());
        user.setRole(node.get("role").asText());
        UserDtls savedUser = userService.saveUser(user);
        System.out.println("User: " + savedUser.toString());
        return ResponseEntity.ok(savedUser);

    }
}
