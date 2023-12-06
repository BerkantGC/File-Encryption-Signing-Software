package com.cybersecurity.assigment.auth;

import com.cybersecurity.assigment.auth.AuthenticationController;
import com.cybersecurity.assigment.model.user.User;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;

@Controller
@RequiredArgsConstructor
@CrossOrigin("http://localhost:8080")
public class AuthenticationController {
    private final AuthenticationService service;
    // Login form
    @GetMapping("/register")
    public String registerPage(Model model) {
       RegisterRequest user =new RegisterRequest();
       model.addAttribute("user", user);

       return "register";
    }

    @PostMapping("/register/save")
    public String register(@ModelAttribute("user") RegisterRequest user) throws NoSuchAlgorithmException {
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

    @GetMapping("/user-info")
    public ResponseEntity<AuthenticationResponse> getUserInfo()
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();

        return ResponseEntity.ok(AuthenticationResponse.builder()
                .id(Long.valueOf(user.getId()))
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .password(user.getPassword())
                .build()
        );
    }
}

