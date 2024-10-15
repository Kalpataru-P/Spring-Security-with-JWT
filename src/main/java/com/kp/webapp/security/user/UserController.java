package com.kp.webapp.security.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @Autowired
    private UserService service;

    @GetMapping("/hello")
    public String hello() {
        return "Welcome to Spring Security";
    }

    @PostMapping("/register")
    public String registerUser(@RequestBody UserInfo user) {
         service.register(user);
        return "User Details register Successfully";
    }

    @PostMapping("/login")
    public String login(@RequestBody UserInfo user) {
        return service.verify(user);
    }





    @PreAuthorize("hasRole('USER')")
    @GetMapping("/auth/user")
    public String userEndpoint() {
        return "Hello";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/auth/admin")
    public String adminEndpoint() {
        return "Hello";
    }
}
