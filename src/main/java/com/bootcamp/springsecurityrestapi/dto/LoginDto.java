package com.bootcamp.springsecurityrestapi.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginDto {
    @NotEmpty
    private String userName;
    @NotEmpty
    private String password;
}
