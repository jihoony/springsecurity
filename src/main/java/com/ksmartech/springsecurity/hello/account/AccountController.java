package com.ksmartech.springsecurity.hello.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AccountController {

    @Autowired
    AccountService accountService;

    @GetMapping(value = "/create")
    public Account create(){
        Account account = new Account();
        account.setEmail("jihoon@mail.com");
        account.setPassword("password");

        return accountService.save(account);
    }
}
