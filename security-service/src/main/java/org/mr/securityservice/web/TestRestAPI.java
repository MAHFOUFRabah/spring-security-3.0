package org.mr.securityservice.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TestRestAPI {

    @GetMapping("/dataTest")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String, Object> data(Authentication authentication) {

        return Map.of(
                "Message", "Data test",
                "username",authentication.getName(),
                "authorities", authentication.getAuthorities()
        );
    }
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    @PostMapping("/saveData")
    public Map<String,String> saveData(Authentication authentication, String data){
        return Map.of("dataSaves",data);
    }
}
