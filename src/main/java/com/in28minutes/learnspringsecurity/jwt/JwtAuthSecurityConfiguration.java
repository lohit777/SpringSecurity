package com.in28minutes.learnspringsecurity.jwt;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//@Configuration
public class JwtAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());//We sare saying any requestr should be authenticated
	//	http.formLogin(withDefaults()); we dont wat to use formlogin for a stateless rest api so we have commented this out
		http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) ;
		//We dont need a session so making it stateless
		http.httpBasic(withDefaults());
		http.csrf().disable() ; //We are duisabling the csrf
		
		http.headers().frameOptions().sameOrigin(); //We are enabling frames if the request comes from the same origin
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt) ; //We are using jwt metjod from OAuth2ResourceServerConfigurer to create a JWT
		//We are conifuring a oAuth2 resource server.
		return http.build();

}



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
//We are generating a keypair
@Bean
public KeyPair keyPair() {
	KeyPairGenerator keyPairGenerator;
	try {
		keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		//We are making use of KeyPairGenerator class to generate keypair
		keyPairGenerator.initialize(2048) ;//We are usi9ng RSA 2048 Encryption. Bigger the size higher the security.
		return keyPairGenerator.generateKeyPair() ;
	} //keypairgenerator will throw exceotion so we kept inside try cartch
	catch (Exception ex) {
		throw new RuntimeException(ex) ;
	}
}
//We are generating a RSA Key object using the keyPair and a library called nimbussds to do RSA encoding and decoding.
@Bean
public RSAKey rsaKey(KeyPair keyPair) {
	return new RSAKey.Builder((RSAPublicKey)keyPair.getPublic())
	.privateKey(keyPair.getPrivate())
	.keyID(UUID.randomUUID().toString())
	.build();
}
//We are creating a JWKSet with a single RSAKey
//After that we will create a JWK Source with the JWKSet
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey) ;
		//We need to override get method in JWKSOURCE to create JWKSource from JWKSet
//		var jwkSource = new JWKSource() {
//
//			@Override
//			public List get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
//				
//				return jwkSelector.select(jwkSet); //We are creating the jwksource with the jwkset 
//			}
//			
//		};
		return (jwkSelector,context) ->jwkSelector.select(jwkSet) ;
	}
	
	//Create decoder bean to decode
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException  {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build() ; //Nimbus accepts both encoders and decoders
		//We are using withPublickey for decoding
	}
	//We are creating a encoder
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource)
	{
		return new NimbusJwtEncoder(jwkSource) ;
	}
}