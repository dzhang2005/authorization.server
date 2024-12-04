package com.oauth2.demo.authorization.server.error;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@AllArgsConstructor
@Getter
@Setter
public class ApiError {
    private int status;
    private String message;
    private LocalDateTime timestamp;
}
