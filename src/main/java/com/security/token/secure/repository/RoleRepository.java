package com.security.token.secure.repository;

import com.security.token.secure.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author JI-Villalobos
 * @version 1.0
 * @since 22/08/2021
 * */

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
