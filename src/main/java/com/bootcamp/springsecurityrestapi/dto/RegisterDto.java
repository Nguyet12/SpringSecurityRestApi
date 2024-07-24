package com.bootcamp.springsecurityrestapi.dto;


import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class RegisterDto {
    @NotEmpty
    private String userName;

    @NotEmpty
    @Size(min = 6,message = "Minimum password length is 6 characters")
    private String password;


    @NotEmpty
    private String email;


}
