package com.in28minutes.learnspringsecurity.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class ToDoResource {
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	List<ToDo> LIST_TODO = List.of(new ToDo("in28minutes","Learn Devops"),
			new ToDo("in28minutes","Learn AWS"));
	@GetMapping("/todos")
	public List<ToDo> retrieveAllToDos() {
		
		return LIST_TODO ;
	}
	
	
	@GetMapping("/users/{username}/todos")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	//We are telling that the below method should be executed
	//only if the logged in user has USER Role and the pathvariable should match username in authenication
	@PostAuthorize("returnObject.username=='in28minutes'") //We are doing a post authorise that the returned object username should be in28minutes
	@RolesAllowed({"ADMIN","USER"}) //We are allowing only admin and User roles by using JSR250 annotation in methodsecurity
	@Secured({"ROLE_ADMIN","ROLE_USER"})
	public ToDo retrieveToDosForSpecificUser(@PathVariable("username") String username) {
		return LIST_TODO.get(0) ;
	}
	@PostMapping("/users/{username}/todos")
	public void  createToDoForSpecificUser(@PathVariable("username") String username,@RequestBody ToDo todo)//We need to give  the pathvariable in the bracket also or else we will get illelagalarmentexception
	//This is because compiler is not able to store the method parameter names while generating the class files
	{
		logger.info("Created {} for {}",username,todo) ;
	}

}

record ToDo(String username,String description){
	
}
