package com.crudJwt.User.jwtController;

import com.crudJwt.User.ExceptionsHandling.ResourceNotFoundException;
import com.crudJwt.User.jwtModel.User;
import com.crudJwt.User.jwtRepository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserRepository userRepository;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public List<User> getAllUsers() {
        logger.info("Fetching all users");
        List<User> users = userRepository.findAll();
        logger.info("Number of users found: {}", users.size());
        return users;
    }

    @PreAuthorize("hasRole('ADMIN') or hasRole('FINANCE')")
    @GetMapping("/{id}")
    public User getUserById(@PathVariable String id) {
        logger.info("Fetching user with ID: {}", id);
        return userRepository.findById(id).orElseThrow(() -> {
            logger.error("User not found with ID: {}", id);
            return new ResourceNotFoundException("User not found");
        });
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public User addUser(@RequestBody User user) {
        logger.info("Adding user: {}", user.getUsername());
        User savedUser = userRepository.save(user);
        logger.info("User added successfully with ID: {}", savedUser.getId());
        return savedUser;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public String deleteUser(@PathVariable String id) {
        logger.info("Deleting user with ID: {}", id);
        userRepository.deleteById(id);
        logger.info("User deleted successfully with ID: {}", id);
        return "User deleted successfully";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public User updateUser(@PathVariable String id, @RequestBody User user) {
        logger.info("Updating user with ID: {}", id);
        User existingUser = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        existingUser.setUsername(user.getUsername());
        existingUser.setRoles(user.getRoles());

        User updatedUser = userRepository.save(existingUser);
        logger.info("User updated successfully with ID: {}", updatedUser.getId());
        return updatedUser;
    }

}
