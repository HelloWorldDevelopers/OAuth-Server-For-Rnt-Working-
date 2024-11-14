package com.OAuth.AuthServer.repo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.OAuth.AuthServer.Entity.EmployeeMaster;

public interface EmployeeMasterRepo extends JpaRepository<EmployeeMaster, Long> {
   Optional<EmployeeMaster> findByUserId(String username);

   @Query(
      value = "SELECT rm.role FROM role_master rm LEFT JOIN user_role ur ON rm.role_id = ur.role_id WHERE ur.deleted_by IS NULL AND ur.end_date>=curdate() AND ur.user_id = ?1",
      nativeQuery = true
   )
   List<String> getRoleList(Long id);
}