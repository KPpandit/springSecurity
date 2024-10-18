package com.crudJwt.User.ExceptionsHandling;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }
}
