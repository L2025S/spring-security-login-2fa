package se.iths.lw.springsecuritylogin2fa.security;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import se.iths.lw.springsecuritylogin2fa.service.AppUserService;
import se.iths.lw.springsecuritylogin2fa.service.CustomUserDetailsService;

import java.io.IOException;

@Component
@AllArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final AppUserService appUserService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String username =authentication.getName();

        boolean twoFactorEnabled = appUserService.isTwoFactorEnabled(username);

        if(twoFactorEnabled) {
            SecurityContextHolder.clearContext();
            request.getSession().invalidate();
            HttpSession newSession = request.getSession(true);
            newSession.setAttribute("tempUsername", username);
            response.sendRedirect("/verify-2fa");
        } else {
            response.sendRedirect("/home");
        }

    }
}

