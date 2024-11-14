package com.OAuth.AuthServer;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Sha1PasswordEncoder implements PasswordEncoder {
   public String encode(CharSequence rawPassword) {
      return this.hashPassword(rawPassword.toString());
   }

   public boolean matches(CharSequence rawPassword, String encodedPassword) {
      String hashedRawPassword = this.hashPassword(rawPassword.toString());
      return hashedRawPassword.equals(encodedPassword);
   }

   private String hashPassword(String password) {
      try {
         MessageDigest digest = MessageDigest.getInstance("SHA-1");
         byte[] hashedBytes = digest.digest(password.getBytes());
         StringBuilder hexString = new StringBuilder();
         byte[] var5 = hashedBytes;
         int var6 = hashedBytes.length;

         for(int var7 = 0; var7 < var6; ++var7) {
            byte b = var5[var7];
            String hex = Integer.toHexString(255 & b);
            if (hex.length() == 1) {
               hexString.append('0');
            }

            hexString.append(hex);
         }

         return hexString.toString();
      } catch (NoSuchAlgorithmException var10) {
         throw new RuntimeException(var10);
      }
   }
}
    