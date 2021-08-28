package com.security.token.secure.service;

import com.security.token.secure.domain.Role;
import com.security.token.secure.domain.AppUser;

import java.util.List;

/**
 * @author JI-Villalobos
 * @version 1.0
 * @since 22/08/2021
 * */

public interface UserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
