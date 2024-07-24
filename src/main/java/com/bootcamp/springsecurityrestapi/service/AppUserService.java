package com.bootcamp.springsecurityrestapi.service;

import com.bootcamp.springsecurityrestapi.domain.AppUser;
import com.bootcamp.springsecurityrestapi.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AppUserService implements UserDetailsService {


    private final AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser= appUserRepository.findByUserName(username);
        if(appUser!=null){
            var springUser= User.withUsername(appUser.getUserName()).password(appUser.getPassword()).roles(appUser.getRole()).build();
            return springUser;
        }
        return null;
    }
}
