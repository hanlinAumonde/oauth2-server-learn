package com.devStudy.oauth2;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class AuthenticationController {
	
	@GetMapping("/home")
    public String home() {
        return "homePage";
    }

	@GetMapping("/secure")
	public String secure(@AuthenticationPrincipal OidcUser principal, Model model) {
	    model.addAttribute("principal", principal);
	    return "secure";
	}
}
