package com.mvas.server.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ServerController {
    @ResponseBody
    @PostMapping("/receiveMessage")
    public String receiveMessage(@RequestParam("message") String message) {

        return message;
    }
}

