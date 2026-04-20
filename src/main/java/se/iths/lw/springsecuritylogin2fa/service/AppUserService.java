package se.iths.lw.springsecuritylogin2fa.service;


import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import se.iths.lw.springsecuritylogin2fa.exception.UserAlreadyExistsException;
import se.iths.lw.springsecuritylogin2fa.model.AppUser;
import se.iths.lw.springsecuritylogin2fa.repository.AppUserRepository;

@Service
@AllArgsConstructor
public class AppUserService {
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;



    public AppUser findByUsername(String username) {

        return appUserRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }

    @Transactional
    public void registerNewUser(String username,
                                String password,
                                String email,
                                boolean twoFactorEnabled,
                                String secret)
    {
        if(appUserRepository.findByUsername(username).isPresent()) {
            throw new UserAlreadyExistsException("Username already exists: " + username);
        }

        AppUser appUser = new AppUser();
        appUser.setUsername(username);
        appUser.setPassword(passwordEncoder.encode(password));
        appUser.setEmail(email);
        appUser.setTwoFactorEnabled(twoFactorEnabled);
        appUser.setSecret(secret);
        appUser.setRole("ROLE_USER");

        appUserRepository.save(appUser);
    }

    /*
    public boolean isTwoFactorEnabled(String username){
        if(!appUserRepository.existsByUsername(username)){
            return false;
        }
        AppUser appUser = findByUsername(username);
        return appUser.isTwoFactorEnabled();

    }

     */

    public boolean isTwoFactorEnabled(String username){
        return appUserRepository.findByUsername(username)
                .map(AppUser::isTwoFactorEnabled)
                .orElse(false);
    }

}
