package com.in28minutes.learnspringsecurity.resources;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class SpringSecurityPlayResources {
	
	@GetMapping("/csrf-token")
	public CsrfToken retrievecsrfToken(HttpServletRequest request)//Here we are wiring the request to the method
	{
		
		return (CsrfToken) request.getAttribute("_csrf") ;
	}
	
	
}
