package com.oauth2.demo.authorization.server.controller;

import com.oauth2.demo.authorization.server.message.MessageResponse;
import com.oauth2.demo.authorization.server.persist.dto.UserRegistrationDto;
import com.oauth2.demo.authorization.server.persist.entity.User;
import com.oauth2.demo.authorization.server.service.impl.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationDto registrationDto) {
        User user = userService.registerNewUser(registrationDto);
        return ResponseEntity.ok(new MessageResponse("User registered successfully"));

    }
}
