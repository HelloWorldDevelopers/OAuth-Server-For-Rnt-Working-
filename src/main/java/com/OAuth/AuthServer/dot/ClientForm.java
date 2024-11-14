package com.OAuth.AuthServer.dot;

public class ClientForm {
	   private String clientId;
	   private String clientSecret;
	   private String redirectUri;

	   public String getClientId() {
	      return this.clientId;
	   }

	   public void setClientId(String clientId) {
	      this.clientId = clientId;
	   }

	   public String getClientSecret() {
	      return this.clientSecret;
	   }

	   public void setClientSecret(String clientSecret) {
	      this.clientSecret = clientSecret;
	   }

	   public String getRedirectUri() {
	      return this.redirectUri;
	   }

	   public void setRedirectUri(String redirectUri) {
	      this.redirectUri = redirectUri;
	   }
	}	