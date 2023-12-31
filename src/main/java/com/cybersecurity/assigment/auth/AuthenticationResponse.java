package com.cybersecurity.assigment.auth;

import com.cybersecurity.assigment.auth.AuthenticationResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    private Long id;
    private String username;
    private String password;
    private String firstName;
    private String lastName;
    private String token;
}
