package com.example.demo.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.demo.service.E2EService;

@Controller
public class WelcomeController {

    @Autowired
    private E2EService e2eService;
    
    @RequestMapping("/aaaa")
    public String welcome(Map<String, Object> model, @RequestParam Map<String, String> param) {
	System.out.println("ggggggg");
	System.out.println("param==>" + param);
	String sk = e2eService.getServerPublicKey("xx", param.get("c"));
	
	System.out.println("sk==>" + sk);
	
	model.put("sk", sk);
	
	return "home";
    }

}