package com.OAuth.AuthServer.Entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Entity
@Table(
   name = "employee_master"
)
public class EmployeeMaster implements UserDetails {
   private static final long serialVersionUID = 1L;
   @Id
   @GeneratedValue(
      strategy = GenerationType.IDENTITY
   )
   @Column(
      name = "staff_id"
   )
   private Long id;
   @Column(
      name = "user_id"
   )
   private String userId;
   @Column(
      name = "password"
   )
   private String password;
   @Column(
      name = "f_name"
   )
   private String fName;
   @Column(
      name = "l_name"
   )
   private String lName;
   @Column(
      name = "m_name"
   )
   private String mName;
   @Column(
      name = "email_id"
   )
   private String emailId;

   public Collection<? extends GrantedAuthority> getAuthorities() {
      return (Collection)Set.of("RNT_USER,NORMAL-USER").stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
   }

   public String getPassword() {
      return this.password;
   }

   public String getUsername() {
      return this.userId;
   }

   public boolean isAccountNonExpired() {
      return true;
   }

   public boolean isAccountNonLocked() {
      return true;
   }

   public boolean isCredentialsNonExpired() {
      return true;
   }

   public boolean isEnabled() {
      return true;
   }

   public Long getId() {
      return this.id;
   }

   public void setId(Long id) {
      this.id = id;
   }

   public String getUserId() {
      return this.userId;
   }

   public void setUserId(String userId) {
      this.userId = userId;
   }

   public String getfName() {
      return this.fName;
   }

   public void setfName(String fName) {
      this.fName = fName;
   }

   public String getlName() {
      return this.lName;
   }

   public void setlName(String lName) {
      this.lName = lName;
   }

   public String getmName() {
      return this.mName;
   }

   public void setmName(String mName) {
      this.mName = mName;
   }

   public void setPassword(String password) {
      this.password = password;
   }

   public String getEmailId() {
      return this.emailId;
   }

   public void setEmailId(String emailId) {
      this.emailId = emailId;
   }
}
    