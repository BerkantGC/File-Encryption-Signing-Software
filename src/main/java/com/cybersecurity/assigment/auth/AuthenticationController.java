package com.cybersecurity.assigment.auth;

import com.cybersecurity.assigment.model.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

//Controller for login and registration pages
@Controller
@RequiredArgsConstructor
@CrossOrigin("http://localhost:8080")
public class AuthenticationController {
    private final AuthenticationService service;
    // Login form
    @GetMapping("/register")
    public String registerPage(Model model) {
        //Creating a new custom register to request to post the user which is about to save
       RegisterRequest user =new RegisterRequest();

       //Sending request as a model to thymeleaf
       model.addAttribute("user", user);

       //Returning to register.html page I've created
       return "register";
    }

    @PostMapping("/register/save")
    public String register(@ModelAttribute("user") RegisterRequest user) throws NoSuchAlgorithmException {

        //Getting model which is updated by thymeleaf page and saving user to database
        service.register(user);
        return "redirect:register?success";
    }
    @RequestMapping("/login")
    public String login(Model model)
    {
        User user = new User();
        model.addAttribute("user", user);

        return "login";
    }
}

