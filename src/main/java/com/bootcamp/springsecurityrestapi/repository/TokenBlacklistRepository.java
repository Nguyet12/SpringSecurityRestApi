package com.bootcamp.springsecurityrestapi.repository;

import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;
@Component
public class TokenBlacklistRepository {
    private Set<String> tokenBlacklist = new HashSet<>();

    public void add(String token) {
        tokenBlacklist.add(token);
    }

    public boolean contains(String token) {
        return tokenBlacklist.contains(token);
    }
}
