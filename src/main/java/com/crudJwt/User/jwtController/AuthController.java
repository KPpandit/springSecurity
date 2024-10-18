package com.crudJwt.User.jwtController;
import com.crudJwt.User.jwtModel.LoginRequest;
import com.crudJwt.User.jwtModel.User;
import com.crudJwt.User.jwtRepository.UserRepository;
import com.crudJwt.User.jwtUtility.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public String register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody LoginRequest loginRequest) {
        System.out.println("login Method is getting hitted");
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        System.out.println(authentication.getDetails() + " authentication details ");
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate access token and refresh token without passing an empty map
        String accessToken = jwtUtil.generateToken(loginRequest.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(loginRequest.getUsername());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        return tokens;
    }



    @PostMapping("/refresh-token")
    public Map<String, String> refreshToken(@RequestParam String refreshToken) {
        Map<String, String> tokens = new HashMap<>();
        try {
            // Validate if the token is a valid refresh token
            String username = jwtUtil.extractUsername(refreshToken);
            boolean isValidRefreshToken = jwtUtil.validateToken(refreshToken, username, "REFRESH_TOKEN");

            if (!isValidRefreshToken) {
                tokens.put("error", "Invalid token type. Please provide a valid refresh token.");
                return tokens;
            }

            // If valid refresh token, generate a new access token
            String newAccessToken = jwtUtil.generateToken(username);
            tokens.put("accessToken", newAccessToken);
        } catch (Exception e) {
            tokens.put("error", e.getMessage());
        }

        return tokens;
    }
}
