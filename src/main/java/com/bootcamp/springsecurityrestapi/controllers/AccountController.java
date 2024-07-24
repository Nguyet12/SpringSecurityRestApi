package com.bootcamp.springsecurityrestapi.controllers;

import com.bootcamp.springsecurityrestapi.domain.AppUser;
import com.bootcamp.springsecurityrestapi.dto.LoginDto;
import com.bootcamp.springsecurityrestapi.dto.RegisterDto;
import com.bootcamp.springsecurityrestapi.repository.AppUserRepository;
import com.bootcamp.springsecurityrestapi.repository.TokenBlacklistRepository;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import javax.swing.text.html.ObjectView;
import java.time.Instant;
import java.util.HashMap;

@RestController
@RequestMapping("/account")
public class AccountController {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.issuer}")
    private String issuer;

    @Autowired
    private  AppUserRepository userRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenBlacklistRepository tokenBlacklistRepository;

    @GetMapping("/profile")
    public ResponseEntity<Object> getProfile(Authentication authentication) {
        var response= new HashMap<String, Object>();
        response.put("username", authentication.getName());
        response.put("authorities", authentication.getAuthorities());

        var appUser = userRepository.findByUserName(authentication.getName());
        response.put("user", appUser);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody @Valid RegisterDto registerDto, BindingResult result) {
        if(result.hasErrors()) {
            var errorList= result.getAllErrors();
            var errorsMap= new HashMap<String,String>();

            for(int i=0;i< errorList.size();i++){
                var error=(FieldError)errorList.get(i);
                errorsMap.put(error.getField(),error.getDefaultMessage());
            }
            return ResponseEntity.badRequest().body(errorsMap);
        }
        var bCrypt = new BCryptPasswordEncoder();
        AppUser appUser= new AppUser();
        appUser.setUserName(registerDto.getUserName());
        appUser.setPassword(bCrypt.encode(registerDto.getPassword()));
        appUser.setEmail(registerDto.getEmail());
        appUser.setRole("client");

        //사용자 존재성 확인
        try {
            //check if username/email are used or not
            var otherUser= userRepository.findByUserName(registerDto.getUserName());
            if(otherUser!=null){
                return ResponseEntity.badRequest().body("Username already used");
            }

            otherUser= userRepository.findByEmail(registerDto.getEmail());
            if(otherUser!=null){
                return ResponseEntity.badRequest().body("Email already used");
            }
            userRepository.save(appUser);

            String jwtToken= createJwtToken(appUser);

            var response= new HashMap<String,Object>();
            response.put("jwtToken",jwtToken);
            response.put("user",appUser);
            return ResponseEntity.ok(response);
        }
        catch (Exception ex){
            System.out.println("there is an exception: ");
            ex.printStackTrace();
        }

        return ResponseEntity.badRequest().body("Error registering user");
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginDto loginDto, BindingResult result){
        if(result.hasErrors()) {
            var errorList= result.getAllErrors();
            var errorsMap= new HashMap<String,String>();
            for(int i=0;i< errorList.size();i++){
                var error=(FieldError)errorList.get(i);
                errorsMap.put(error.getField(),error.getDefaultMessage());
            }
            return ResponseEntity.badRequest().body(errorsMap);
        }
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getUserName(),
                            loginDto.getPassword()
                    )
            );

            AppUser appUser= userRepository.findByUserName(loginDto.getUserName());
            String jwtToken= createJwtToken(appUser);

            var response= new HashMap<String,Object>();
            response.put("jwtToken",jwtToken);
            response.put("user",appUser);
            return ResponseEntity.ok(response);
        }
        catch (Exception ex){
            System.out.println("there is an exception: ");
            ex.printStackTrace();
        }
        return  ResponseEntity.badRequest().body("Bad username or password");


    }

    @PostMapping("/logout")
    public ResponseEntity<Object> logout(HttpServletRequest request){
        if (request == null) {
            return ResponseEntity.badRequest().body("User is not authenticated");
        }

        String token = extractTokenFromAuthentication(request);

        if (token != null) {
            tokenBlacklistRepository.add(token);
            return ResponseEntity.ok("Logged out successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid token");
        }
    }
    private String extractTokenFromAuthentication(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }



    private String createJwtToken(AppUser appUser){
        Instant now= Instant.now();

        JwtClaimsSet claims= JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds((24*3600)))
                .subject(appUser.getUserName())
                .claim("role",appUser.getRole())
                .build();

        var encoder= new NimbusJwtEncoder(
                new ImmutableSecret<>(secretKey.getBytes()));

        var param= JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),claims);

        return encoder.encode(param).getTokenValue();
    }
}
