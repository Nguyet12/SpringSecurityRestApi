package com.bootcamp.springsecurityrestapi.domain;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Table(name = "users")
@Getter
@Setter
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(name = "user_name",unique = true)
    private String userName;

    private String password;

    @Column(unique = true,nullable = false)
    private String email;

    private String role;
    private Date createdAt;
}
