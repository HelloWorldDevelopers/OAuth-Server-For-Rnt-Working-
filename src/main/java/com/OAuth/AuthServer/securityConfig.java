package com.OAuth.AuthServer;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizedUrl;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.OAuth.AuthServer.Entity.Clients;
import com.OAuth.AuthServer.Entity.EmployeeMaster;
import com.OAuth.AuthServer.Entity.RdirectUrls;
import com.OAuth.AuthServer.repo.ClientsRepo;
import com.OAuth.AuthServer.repo.EmployeeMasterRepo;
import com.OAuth.AuthServer.serviceImpl.ClientService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.RSAKey.Builder;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class securityConfig {
   private final EmployeeMasterRepo userRepository;
   private final ClientService clientList;
   @Autowired
   private ClientsRepo clientsRepo;

   public securityConfig(EmployeeMasterRepo userRepository, ClientService clientList) {
      this.userRepository = userRepository;
      this.clientList = clientList;
   }

   @Bean
   @Order(1)
   public SecurityFilterChain webFilterChainForOAuth(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
      http.sessionManagement((session) -> {
         session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).maximumSessions(5000).expiredSessionStrategy((event) -> {
         });
      });
      ((OAuth2AuthorizationServerConfigurer)http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)).oidc(Customizer.withDefaults());
      http.exceptionHandling((e) -> {
         e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
      });
      return (SecurityFilterChain)http.build();
   }

   @Order(2)
   @Bean
   public SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
      http.authorizeHttpRequests((request) -> {
         ((AuthorizedUrl)((AuthorizedUrl)request.requestMatchers(new String[]{"/submit-url", "/register", "/addClients", "/clients/add", "/public/**", "/applicationList", "/deleteRedirectUrl/**"})).permitAll().anyRequest()).authenticated();
      }).formLogin((form) -> {
         form.loginPage("/login").permitAll();
      });
      return (SecurityFilterChain)http.build();
   }

   @Bean
   public UserDetailsService userDetailsService() {
      return (username) -> {
         return (UserDetails)this.userRepository.findByUserId(username).map((user) -> {
            return new User(user.getUsername(), user.getPassword(), user.getAuthorities());
         }).orElseThrow(() -> {
            return new UsernameNotFoundException("User not found");
         });
      };
   }

   @Bean
   public PasswordEncoder passwordEncoder() {
      return new Sha1PasswordEncoder();
   }

   @Bean
   public RegisteredClientRepository registeredClientRepository() {
      ArrayList<RegisteredClient> clients = new ArrayList();
      Iterator var2 = this.clientsRepo.findAll().iterator();

      while(var2.hasNext()) {
         Clients cl = (Clients)var2.next();
         RegisteredClient registerClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(cl.getClientId()).clientSecret(cl.getSecretKey()).redirectUris(this.getUrls(cl.getRdirectUrls())).scope("openid").scope("profile").clientAuthenticationMethod(ClientAuthenticationMethod.NONE).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).authorizationGrantTypes((type) -> {
            type.add(AuthorizationGrantType.AUTHORIZATION_CODE);
            type.add(AuthorizationGrantType.REFRESH_TOKEN);
            type.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
         }).clientSettings(ClientSettings.builder().requireProofKey(true).build()).build();
         clients.add(registerClient);
      }

      return new InMemoryRegisteredClientRepository(clients);
   }

   private Consumer<Set<String>> getUrls(Set<RdirectUrls> list) {
      return (urls) -> {
         if (list.isEmpty()) {
            urls.add("http://localhost:8080/test");
         } else {
            Iterator var2 = list.iterator();

            while(var2.hasNext()) {
               RdirectUrls redirectUrl = (RdirectUrls)var2.next();
               urls.add(redirectUrl.getRedirectUri());
            }
         }

      };
   }

   @Bean
   public AuthorizationServerSettings authorizationServerSettings() {
      return AuthorizationServerSettings.builder().build();
   }

   @Bean
   public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keys = keyPairGenerator.generateKeyPair();
      RSAPublicKey publicKey = (RSAPublicKey)keys.getPublic();
      PrivateKey privateKey = keys.getPrivate();
      RSAKey rsaKey = (new Builder(publicKey)).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
      JWKSet jwkSet = new JWKSet(rsaKey);
      return new ImmutableJWKSet(jwkSet);
   }

   @Bean
   public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
      return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
   }

   @Bean
   public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
      System.out.println("Creating AuthenticationManager bean");
      return (AuthenticationManager)((AuthenticationManagerBuilder)((DaoAuthenticationConfigurer)((AuthenticationManagerBuilder)http.getSharedObject(AuthenticationManagerBuilder.class)).userDetailsService(this.userDetailsService()).passwordEncoder(this.passwordEncoder())).and()).build();
   }

   @Bean
   public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
      return (context) -> {
         if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            Authentication authentication = context.getPrincipal();
            if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
               UserDetails userDetails = (UserDetails)authentication.getPrincipal();
               Optional<EmployeeMaster> findByUsername = this.userRepository.findByUserId(userDetails.getUsername());
               if (findByUsername.isPresent()) {
                  context.getClaims().claims((claims) -> {
                     claims.put("userId", userDetails.getUsername());
                     claims.put("staffId", ((EmployeeMaster)findByUsername.get()).getId());
                     String var10002 = ((EmployeeMaster)findByUsername.get()).getfName();
                     claims.put("fullName", var10002 + " " + ((EmployeeMaster)findByUsername.get()).getlName());
                     claims.put("emailId", ((EmployeeMaster)findByUsername.get()).getEmailId());
                  });
                  Instant now = Instant.now();
                  Instant expirationTime = now.plus(Duration.ofDays(365L));
                  context.getClaims().expiresAt(expirationTime);
               }
            }
         }

      };
   }
}