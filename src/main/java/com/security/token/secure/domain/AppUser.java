package com.security.token.secure.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

/**
 * @author JI-Villalobos
 * @version 1.0
 * @since 22/08/2021
 * */


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "app_user") //don't use "user" never as column name in postgres dialect
public class AppUser {

    @SequenceGenerator(
            name = "user_sequence",
            sequenceName = "user_sequence",
            allocationSize = 1
    )
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "user_sequence"
    )
    private Long id;
    private String name;
    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER) //fetch to load all the roles of the user
    @JoinColumn(
            nullable = false,
            name = "app_user_roles"
    )
    private Collection<Role> roles = new ArrayList<>();
}
