package com.OAuth.AuthServer.Controller;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.OAuth.AuthServer.Entity.Clients;
import com.OAuth.AuthServer.Entity.RdirectUrls;
import com.OAuth.AuthServer.dot.ClientForm;
import com.OAuth.AuthServer.repo.ClientsRepo;
import com.OAuth.AuthServer.repo.RedirectUrlsRepo;

import jakarta.transaction.Transactional;

@Controller
public class LoginController {
   @Autowired
   private ClientsRepo clientsRepo;
   @Autowired
   private RedirectUrlsRepo redirectUrlsRepo;

   @GetMapping({"/login"})
   public ModelAndView loginPage() {
      return new ModelAndView("login");
   }

   @GetMapping({"/register"})
   public String showRegistrationForm(Model model) {
      model.addAttribute("client", new ClientForm());
      return "register";
   }

   @PostMapping({"/addClients"})
   @Transactional
   public String registerClient(@ModelAttribute("client") ClientForm clientForm, Model model, RedirectAttributes redirectAttributes) {
      System.out.println("Client ID: " + clientForm.getClientId());
      System.out.println("Client Secret: " + clientForm.getClientSecret());
      System.out.println("Redirect URI: " + clientForm.getRedirectUri());
      Clients cli = new Clients();
      cli.setClientId(clientForm.getClientId());
      cli.setSecretKey(clientForm.getClientSecret());
      cli.setRdirectUrls(this.getUrls(clientForm.getRedirectUri()));
      Clients save = (Clients)this.clientsRepo.save(cli);
      if (Objects.nonNull(save)) {
         redirectAttributes.addFlashAttribute("success", true);
         redirectAttributes.addFlashAttribute("message", "Redirect URL saved successfully!");
      } else {
         redirectAttributes.addFlashAttribute("success", false);
         redirectAttributes.addFlashAttribute("message", "Redirect URL Not Saved!");
      }

      redirectAttributes.addFlashAttribute("message", "Client registered successfully!");
      redirectAttributes.addFlashAttribute("success", true);
      return "redirect:/register";
   }

   private Set<RdirectUrls> getUrls(String redirectUri) {
      Set<RdirectUrls> urls = new HashSet();
      RdirectUrls rdirectUrls = new RdirectUrls();
      rdirectUrls.setRedirectUri(redirectUri);
      urls.add(rdirectUrls);
      return urls;
   }

   @GetMapping({"/applicationList"})
   public String applicationList(Model model) {
      model.addAttribute("list", this.clientsRepo.findAll());
      return "applicationList";
   }

   @GetMapping({"/deleteRedirectUrl/{id}"})
   public String deleteRedirectUrl(@PathVariable("id") String urlId) {
      this.redirectUrlsRepo.deleteById(Long.parseLong(urlId));
      return "redirect:/applicationList";
   }

   @PostMapping({"/submit-url"})
   public String submitRedirectUrl(@RequestParam String redirectUrl, @RequestParam String clientId, Model model, RedirectAttributes attributes) {
      Clients clients = (Clients)this.clientsRepo.findById(Long.valueOf(clientId)).get();
      RdirectUrls rdirectUrls = new RdirectUrls();
      rdirectUrls.setRedirectUri(redirectUrl);
      clients.getRdirectUrls().add(rdirectUrls);
      Clients save = (Clients)this.clientsRepo.save(clients);
      if (Objects.nonNull(save)) {
         attributes.addFlashAttribute("success", true);
         attributes.addFlashAttribute("message", "Redirect URL saved successfully!");
      } else {
         attributes.addFlashAttribute("success", false);
         attributes.addFlashAttribute("message", "Redirect URL Not Saved!");
      }

      return "redirect:/applicationList";
   }
}