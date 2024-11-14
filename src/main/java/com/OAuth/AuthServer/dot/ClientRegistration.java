package com.OAuth.AuthServer.dot;

import java.util.List;

public class ClientRegistration {
   private String clientId;
   private String secretKey;
   private List<String> redirectUrls;

   public String getClientId() {
      return this.clientId;
   }

   public void setClientId(String clientId) {
      this.clientId = clientId;
   }

   public String getSecretKey() {
      return this.secretKey;
   }

   public void setSecretKey(String secretKey) {
      this.secretKey = secretKey;
   }

   public List<String> getRedirectUrls() {
      return this.redirectUrls;
   }

   public void setRedirectUrls(List<String> redirectUrls) {
      this.redirectUrls = redirectUrls;
   }
}