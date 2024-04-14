package com.in28minutes.learnspringsecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;

//We are trying to get a JWT Token using basic auth so that this will be sent as Bearer token for authenicating requests
//This resource will create JWT for us
//@RestController
public class JwtAuthenicationResource {
	private JwtEncoder jwtEncoder ;
	public  JwtAuthenicationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder =jwtEncoder ;
	}
	
	@PostMapping("/authenicate")
	public JwtResponse authenicate(Authentication authenication) ///It will accept a Authentication object
	{
		return new JwtResponse(createToken(authenication)) ; //We are returning a jwtresponse based on the authenticateion after creating a token
	}

	private String createToken(Authentication authenication)//This authenication is taken from the 1
	 {
		var claims = JwtClaimsSet.builder()
		.issuer("self")  //Who is creating the token
		.issuedAt(Instant.now()) //When its created
		.expiresAt(Instant.now().plusSeconds(15*60)) //when it will expire
		.subject(authenication.getName()) 
		.claim("scope",createScope(authenication))  //get the scope of the user admin/user
		.build() ;
		
		JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);
		return jwtEncoder.encode(parameters ).getTokenValue(); //We are getting the token using the claimset by passing paramenter like 
		//the user ,issuer ,time of generation of token 
		//We are encoding the parameters and ggetting the token value back
	}

	private String createScope(Authentication authenication) {
		return authenication.getAuthorities().stream()   //We are trying to get all the authorities for a particular user
		.map(a ->a.getAuthority())  //We are mapping each authority and collecting all the authorities of the user  into a string 
		.collect(Collectors.joining(" ")) ;
		
	}

}

record JwtResponse(String token) {}