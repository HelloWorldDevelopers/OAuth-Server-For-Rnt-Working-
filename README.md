This url is convert your .class file to actual java code (when your code delete and you have only .war file then you get war file and convert zip then extract this zip file then 
get .class file and upload below link and get .java file)
https://www.decompiler.com/jar/




http://localhost:8080/auth-server/.well-known/openid-configuration

http://localhost:8080/auth-server/oauth2/authorize
?client_id=client
&response_type=code
&scope=openid
&redirect_uri=http://localhost:3000/redirect
&code_challenge=oQrh6L3PcIswZuWVW4y_Vlh-vYsKPW3vmBwZyHugeKU
&code_challenge_method=S256




http://localhost:8080/auth-server/oauth2/authorize
?client_id=client
&response_type=code
&scope=openid
&redirect_uri=http://localhost:3000/redirect
&code_challenge=PSmzPvR1tHDUtLJTDaxHb_hASGV1xhcxd3kroUc2c30
&code_challenge_method=S256




http://localhost:8080/auth-server/.well-known/openid-configuration


 


http://localhost:8080/auth-server/oauth2/token?grant_type=authorization_code&client_id=client&code=fL80ObPqi3jva8UV4f79OKgDbKXZBhVZuv8skrulmA1VOluxdrGUrfSDvosHQpfYv_U1yB6iSuKw4XaaEfFeh5auGq6TmRuYkA8QXvuHzJZJrbinhFT8DiJqupV_FnVU&redirect_uri=http://localhost:3000/redirect&code_verifier=EUDEwMyzAoUSaGLhwKwwUi1eZ3uGIT0cuR0xfwFTx1EboYr4C1ce-93GOHbUN3IL7gYzEXnzeNCjIRAwuiPPifNBDIRPIvO6lrlRo93k0_8PJi1GfJvCaUaln5Mpus4b









THis url hit form front-end

// src/Login.js
import React, { useEffect } from 'react';

const Login = () => {
  useEffect(() => {
     const clientId = 'client';
    const redirectUri = 'http://localhost:3000/redirect'; // Ensure this matches your registered redirect URI
    const authorizationEndpoint = 'http://localhost:8080/auth-server/oauth2/authorize';
    const codeChallenge = 'PSmzPvR1tHDUtLJTDaxHb_hASGV1xhcxd3kroUc2c30'; // Ensure this matches the challenge used during authorization

    const authorizationRequest = `${authorizationEndpoint}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=openid&code_challenge=${codeChallenge}&code_challenge_method=S256`;

    window.location.href = authorizationRequest; // Automatically redirect to authorization server
  }, []);

  return <div>Redirecting to login...</div>;
};
 
export default Login;


-------------------------hit form backend



package com.client.jd;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Principal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@CrossOrigin(allowedHeaders = "*",origins = "*")
@RestController
public class HomeController {

	@GetMapping("/message")
	public ResponseEntity<?> getMessage(Principal principal) {
		  Map<String, Object> map=new HashMap<String, Object>();
		  
		  System.err.println(principal.getName());
		  List<Student> students = new ArrayList<>();

	        // Add 10 student records to the list
	        students.add(new Student(1L, "John Doe", "johndoe@example.com", LocalDate.of(2000, 1, 15), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(2L, "Jane Smith", "janesmith@example.com", LocalDate.of(1999, 2, 20), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(3L, "Mike Johnson", "mikejohnson@example.com", LocalDate.of(2001, 3, 10), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(4L, "Emily Davis", "emilydavis@example.com", LocalDate.of(2000, 4, 25), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(5L, "Chris Brown", "chrisbrown@example.com", LocalDate.of(1998, 5, 30), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(6L, "Sarah Wilson", "sarahwilson@example.com", LocalDate.of(2001, 6, 12), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(7L, "David Lee", "davidlee@example.com", LocalDate.of(1999, 7, 18), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(8L, "Laura White", "laurawhite@example.com", LocalDate.of(2000, 8, 22), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(9L, "James Green", "jamesgreen@example.com", LocalDate.of(2002, 9, 14), LocalDate.of(2024, 9, 1)));
	        students.add(new Student(10L, "Olivia Martinez", "oliviamartinez@example.com", LocalDate.of(1998, 10, 28), LocalDate.of(2024, 9, 1)));

		  
	        map.put("data", students);
	        map.put("logged_by", principal.getName());
	        return new ResponseEntity<>(map,HttpStatus.OK);
 	}
	
	  @GetMapping("/redirect")
	    public ResponseEntity<?> redirect(@RequestParam("code") String code) throws IOException, InterruptedException {
	      
		  System.err.println("----------------------------"+code);
		  
		  String clientId = "client";
	        String clientSecret = "secret"; // Optional for public clients, may be empty
	        String tokenEndpoint = "http://localhost:8080/auth-server/oauth2/token"; // Example for Google
	        String redirectUri = "http://localhost:3000/redirect";

	        // Retrieve the code verifier from the session or wherever it was stored
	        String codeVerifier = "EUDEwMyzAoUSaGLhwKwwUi1eZ3uGIT0cuR0xfwFTx1EboYr4C1ce-93GOHbUN3IL7gYzEXnzeNCjIRAwuiPPifNBDIRPIvO6lrlRo93k0_8PJi1GfJvCaUaln5Mpus4b";

	        // Create the token request
	        HttpClient client = HttpClient.newHttpClient();
	        HttpRequest tokenRequest = HttpRequest.newBuilder()
	                .uri(URI.create(tokenEndpoint))
	                .header("Content-Type", "application/x-www-form-urlencoded")
	                .POST(HttpRequest.BodyPublishers.ofString(
	                        "grant_type=authorization_code" +
	                        "&code=" + code +
	                        "&redirect_uri=" + URLEncoder.encode(redirectUri, "UTF-8") +
	                        "&client_id=" + clientId +
	                        "&code_verifier=" + codeVerifier
	                ))
	                .build();

	        HttpResponse<String> tokenResponse = client.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
	        String responseBody = tokenResponse.body();

	        ObjectMapper mapper = new ObjectMapper();
	        JsonNode jsonNode = mapper.readTree(responseBody);
	        String idToken = jsonNode.get("id_token").asText();
	        String accessToken = jsonNode.get("access_token").asText();

	        // Use the tokens to authenticate the user and create a session
	        // For simplicity, you can just return the ID token here, but in practice, you would process this further
         Map<String, String> map=new HashMap<String, String>();
        map.put("token", accessToken);
        return new ResponseEntity<>(map,HttpStatus.OK);
        
    }

}
--------------------------------config security----------------------------
package com.client.jd;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class securityConfig {

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.cors();
        httpSecurity
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/redirect/**").permitAll() // Allow access to your redirect API
                .anyRequest().authenticated() // Secure other endpoints
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );
        return httpSecurity.build();
    }
	@Bean
	public JwtDecoder jwtDecoder() {
		NimbusJwtDecoder jwtDecoder=NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/auth-server/oauth2/jwks")
				.build();
		return jwtDecoder;
				
	}
}
----------------------------------------pom.xml---------------------------
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.3.3</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.client</groupId>
	<artifactId>demo</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>demo</name>
	<description>Demo project for Spring Boot</description>
	<url/>
	<licenses>
		<license/>
	</licenses>
	<developers>
		<developer/>
	</developers>
	<scm>
		<connection/>
		<developerConnection/>
		<tag/>
		<url/>
	</scm>
	<properties>
		<java.version>17</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>

</project>



















