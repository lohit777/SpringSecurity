package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(jsr250Enabled=true,securedEnabled=true) //We are enabling methodsecurity using jsr250annotation andd secureenabled
public class BasicAuthSecurityConfiguration {
//	@Bean
//	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
//		http.formLogin(withDefaults());
//		http.httpBasic(withDefaults());
//		return http.build();  //This entire code is copied from SpringBootWebSecurityConfiguration
		//class which have default security filters like basic authentication enabling form based login, csrf ,basic authentication
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
				//.requestMatchers("/users").hasRole("USER") //In this we are checking whether we have users keyword in url and the role of user is user
				.anyRequest().authenticated());//We sare saying any requestr should be authenticated
	//	http.formLogin(withDefaults()); we dont wat to use formlogin for a stateless rest api so we have commented this out
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) ;
		//We dont need a session so making it stateless
		http.httpBasic(withDefaults());
		http.csrf().disable() ; //We are duisabling the csrf
		
		http.headers().frameOptions().sameOrigin(); //We are enabling frames if the request comes from the same origin
		return http.build();

}

//HttpSecurity is the class which helps to configure the filter chain

//@Bean
//public UserDetailsService userDetailsService() {
//	var user = User.withUsername("in28minutes")
//	.password("{noop}dummy") //We are hardcoding the password so we gave noop here in {} so that no operation will be performed
//	.roles("USER")
//	.build() ; //We are configutring user details here instead of application.properties
//	
//	var admin = User.withUsername("admin")
//			.password("{noop}dummy") //We are hardcoding the password so we gave noop here in {} so that no operation will be performed
//			.roles("ADMIN")
//			.build() ;
//	return new InMemoryUserDetailsManager(user,admin) ;
//	//We are passing both the users to InMemoryUserDetailsManager
//}
//UserDetailsService is the core interface which loads user specific data.If you want userdetails this is the interface you need
//InMemoryUserDetailsManager is the non persistance implementation of the userdetailsmanager

@Bean
public DataSource dataSource() {
	return new EmbeddedDatabaseBuilder() //This helps to create a new embedded database
			.setType(EmbeddedDatabaseType.H2)  //We want to connect to a H2 Database
			.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)  //We are executing the database before the start of our application
			.build();
}


//We are storing our credentials in a database
@Bean
public UserDetailsService userDetailsService(DataSource dataSource) {
	var user = User.withUsername("in28minutes")
	//.password("{noop}dummy") //We are hardcoding the password so we gave noop here in {} so that no operation will be performed
	.password("dummy")
	.passwordEncoder(str -> passwordEncoder().encode(str) )
			.roles("USER")
	.build() ; //We are configutring user details here instead of application.properties
	
	var admin = User.withUsername("admin")
			//.password("{noop}dummy") //We are hardcoding the password so we gave noop here in {} so that no operation will be performed
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str) ) //Here we are encoding the password so that the password will not be visible to end user
			.roles("ADMIN")
			.build() ;
	
	var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
	jdbcUserDetailsManager.createUser(user);
	jdbcUserDetailsManager.createUser(admin);
	return jdbcUserDetailsManager ; //Instead of using inmemoryuserdteailsmanager we are using jdbcuserdetailsmanager which will get the user details from jdbc
	//return new InMemoryUserDetailsManager(user,admin) ;
	//We are passing both the users to InMemoryUserDetailsManager
}

@Bean //It is a password hashing technique used to store passwords
public  BCryptPasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder() ;
}
}