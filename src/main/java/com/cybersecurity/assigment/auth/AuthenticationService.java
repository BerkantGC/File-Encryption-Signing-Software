package com.cybersecurity.assigment.auth;


import com.cybersecurity.assigment.auth.config.JwtService;
import com.cybersecurity.assigment.model.user.Role;
import com.cybersecurity.assigment.model.user.User;
import com.cybersecurity.assigment.repository.UserRepository;
import com.cybersecurity.assigment.service.keys.KeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor

public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final KeyService keyService;

    //Saving new user to database
    public AuthenticationResponse register(RegisterRequest request) throws NoSuchAlgorithmException {
        //Generating a new unique keypair for user
        KeyPair keyPair = keyService.generateRSAKey();

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .privateKey(keyPair.getPrivate().getEncoded()) //giving users private key
                .publicKey(keyPair.getPublic().getEncoded())//giving users public key
                .role(Role.USER)
                .build();
        userRepository.save(user); //saving user
        var jwtToken = jwtService.generateToken(user); //generating users token key
        return AuthenticationResponse.builder().token(jwtToken).build(); //response of created user
    }

}
