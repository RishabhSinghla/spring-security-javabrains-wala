package com.springrest.springrest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SuppressWarnings("deprecation")
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	// for authorization to website we create users and passwords with this method
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		// this below is for in memory authentication

//		auth.inMemoryAuthentication()
//			.withUser("blah")
//			.password("blah") --------> .password(this.getPasswordEncoder().encode("blah") ---> this is if we use BCrypt password encoder
//			.roles("USER")
//			.and()
//			.withUser("foo")
//			.password("foo")
//			.roles("ADMIN");

		// this below is for database authentication, to get user and password from
		// MySQL database

		auth.userDetailsService(userDetailsService);

		// this below is for database authentication, to get user and password from H2
		// database

//		auth.jdbcAuthentication()
//			.dataSource(dataSource)
//			.withDefaultSchema()
//			.withUser(
//					User.withUsername("user")
//					.password("pass")
//					.roles("USER")
//			)
//			.withUser(
//					User.withUsername("admin")
//					.password("pass")
//					.roles("ADMIN")
//			);
	}

	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	// if we want to use bcrypt password encoder
	
//	@Bean
//	public PasswordEncoder getPasswordEncoder() {
//		return new BCryptPasswordEncoder(10);
//	}

	// for authorization to specific urls like /, /admin, /user we use this method
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/admin").hasRole("ADMIN").antMatchers("/user").hasAnyRole("USER", "ADMIN")
				.antMatchers("/").permitAll().and().formLogin();
	}
}
