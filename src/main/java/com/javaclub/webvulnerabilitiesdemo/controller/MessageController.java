package com.javaclub.webvulnerabilitiesdemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Controller
public class MessageController {
    private static final List<String> messages = new ArrayList<>();

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/messages")
    public String messages(final Model model) {
        model.addAttribute("messages", messages);

        return "messages";
    }

    @PostMapping("/messages")
    public String addMessage(final Model model, final String message) {
        messages.add(message);
        model.addAttribute("messages", messages);
        log.info("New message: {}", message);

        return "messages";
    }

    @GetMapping("/unauthorized")
    public String unauthorized(final Model model) {
        model.addAttribute("error", "You are not authorized to access this page.");

        return "unauthorized";
    }
}
