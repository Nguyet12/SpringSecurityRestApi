package com.bootcamp.springsecurityrestapi.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "Welcome to Spring Security Rest Api";
    }

    @GetMapping("/store")
    public String store() {
        return "Welcome to Store";
    }

    @GetMapping("/admin/home")
    public String adminHome() {
        return "Welcome to Admin Home";
    }

    @GetMapping("/client/home")
    public String clientHome() {
        return "Welcome to Client Home";
    }
}
