package se.iths.lw.springsecuritylogin2fa.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import se.iths.lw.springsecuritylogin2fa.model.AppUser;
import se.iths.lw.springsecuritylogin2fa.service.AppUserService;
import se.iths.lw.springsecuritylogin2fa.service.TwoFactorService;

import java.util.Collections;

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
            return "register";
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
    @GetMapping("/qrcode/image")
    @ResponseBody
    public ResponseEntity<byte[]> getQrCodeImage(@RequestParam String username,
                                                 @RequestParam String secret){
        String issuer ="Spring Security Login 2FA";
        String otpUri = twoFactorService.getOtpAuthUri(secret, username,issuer);
        byte[] qrCode = twoFactorService.generateQrCodeImage(otpUri, 200,200);
        return ResponseEntity.ok()
                .contentType(MediaType.IMAGE_PNG)
                .body(qrCode);
    }

    @GetMapping("/login")
    public String showLoginForm(
            @RequestParam(value="error", required = false)String error,
            @RequestParam(value="logout",required = false) String logout,
            Model model){
        if(error!=null) {
            model.addAttribute("error", "Invalid username or password");
        }
        if(logout != null){
            model.addAttribute("message", "You have been logged out.");
        }
        return "login";
    }

    @GetMapping("/verify-2fa")
    public String showTwoFactorPage(HttpSession httpSession, Model model) {
        String tempUsername=(String)httpSession.getAttribute("tempUsername");
        if(tempUsername == null) {
            return "redirect:/login?expired";
        }
        model.addAttribute("username", tempUsername);
        return "verify-2fa";

    }
    @PostMapping("/verify-2fa/submit")
            public String verifyTwoFactorCode(@RequestParam("code")String code,
                                              HttpSession httpSession,
                                              HttpServletRequest httpServletRequest){
        String username =(String) httpSession.getAttribute("tempUsername");
        if(username == null) {
            return "redirect:/login";
        }
        AppUser appUser= appUserService.findByUsername(username);
        if(appUser == null || !appUser.isTwoFactorEnabled()){
            return "redirect:/login";
        }

        boolean isValid;
        try{
            int verificationCode=Integer.parseInt(code);
            isValid = twoFactorService.verifyTotpCode(appUser.getSecret(),verificationCode);
        } catch(NumberFormatException e) {
            isValid = false;
        }
        if(isValid){
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            appUser.getUsername(),
                            null,
                            Collections.singletonList(new SimpleGrantedAuthority(appUser.getRole()))
                    );
            SecurityContextHolder.getContext().setAuthentication(authToken);
            httpSession.removeAttribute("tempUsername");

            httpServletRequest.getSession().setAttribute("SPRING_SECURITY_CONTEXT",SecurityContextHolder.getContext());
            return "redirect:/home";
        } else {
            return "redirect:/verify-2fa?error";
        }
    }

    @GetMapping("/home")
    public String home(){
        return "home";
    }


}
