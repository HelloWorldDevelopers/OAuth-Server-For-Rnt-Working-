package com.OAuth.AuthServer.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.OAuth.AuthServer.Entity.Clients;

public interface ClientsRepo extends JpaRepository<Clients, Long> {
}