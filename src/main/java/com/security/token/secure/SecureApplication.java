package com.security.token.secure;

import com.security.token.secure.domain.Role;
import com.security.token.secure.domain.AppUser;
import com.security.token.secure.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SecureApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new AppUser(null, "Jhonny Damn", "jhon", "1245354", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Paul Larusso", "pala", "1245354", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Jhaa Dhamner", "jharul", "1245354", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Ana Rieev", "anamore", "1245354", new ArrayList<>()));

			userService.addRoleToUser("jhon", "ROLE_USER");
			userService.addRoleToUser("jhon", "ROLE_MANAGER");
			userService.addRoleToUser("pala", "ROLE_MANAGER");
			userService.addRoleToUser("jharul", "ROLE_ADMIN");
			userService.addRoleToUser("jharul", "ROLE_MANAGER");
			userService.addRoleToUser("anamore", "ROLE_SUPER_ADMIN");
		};
	}

}
