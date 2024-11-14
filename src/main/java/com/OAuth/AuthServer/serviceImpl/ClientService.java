package com.OAuth.AuthServer.serviceImpl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.OAuth.AuthServer.Entity.Clients;
import com.OAuth.AuthServer.repo.ClientsRepo;

@Component
public class ClientService {
   @Autowired
   private ClientsRepo clientsRepo;

   public List<Clients> getAllClients() {
      return this.clientsRepo.findAll();
   }
}