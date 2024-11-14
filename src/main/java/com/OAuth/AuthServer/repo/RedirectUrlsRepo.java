package com.OAuth.AuthServer.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.OAuth.AuthServer.Entity.RdirectUrls;

public interface RedirectUrlsRepo extends JpaRepository<RdirectUrls, Long> {
}