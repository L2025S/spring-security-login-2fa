package se.iths.lw.springsecuritylogin2fa.controller;


import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.lw.springsecuritylogin2fa.model.AppUser;
import se.iths.lw.springsecuritylogin2fa.service.AppUserService;
import se.iths.lw.springsecuritylogin2fa.service.TwoFactorService;

@Controller
@AllArgsConstructor
public class AuthController {

    private final AppUserService appUserService;
    private final TwoFactorService twoFactorService;

    @GetMapping("/register")
    public String showRegistrationForm(Model model){
        model.addAttribute("appUser", new AppUser());
        return "register";
    }

    @PostMapping("/register/submit")
    public String registerUser(
            @Valid @ModelAttribute("appUser") AppUser appUser,
            BindingResult bindingResult,
            @RequestParam(value="twoFactorEnabled", defaultValue="false") boolean twoFactorEnabled,
            Model model) {
        if(bindingResult.hasErrors()){
            return "regsitser";
        }
        try{
            String secret = null;
            if(twoFactorEnabled){
                secret = twoFactorService.generateSecret();
            }
            appUserService.registerNewUser(
                    appUser.getUsername(),
                    appUser.getPassword(),
                    twoFactorEnabled,
                    secret
            );

            if(twoFactorEnabled){
                return "redirect:/qrcode?username="+appUser.getUsername() +"&secret=" +secret;
            }
            return "redirect:/login?registered";
        } catch(Exception e){
            model.addAttribute("error",e.getMessage());
            return "register";
        }

    }

    @GetMapping("/qrcode")
    public String showQrCode(@RequestParam String username,
                             @RequestParam String secret,
                             Model model) {
        model.addAttribute("username", username);
        model.addAttribute("secret", secret);
        return "qrcode";
    }


}
