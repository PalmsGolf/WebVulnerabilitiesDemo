package com.javaclub.webvulnerabilitiesdemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MessageXssController {

    @GetMapping("/submit")
    public String submitXss(@RequestParam(name = "name") final String name, final Model model) {
        model.addAttribute("name", name);

        return "messagesXss";
    }
}
