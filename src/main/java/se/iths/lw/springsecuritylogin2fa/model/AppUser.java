package se.iths.lw.springsecuritylogin2fa.model;


import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Objects;

@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@Entity
@Table(name="app_user_2fa")
public class AppUser {

    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id;



    @Column(unique=true, nullable=false, length =255)
    private String username;


    @Column(nullable=false, length = 1000)
    private String password;

    private String role;


    @Column(length = 255, nullable=false)
    private String email;

    @Column(name="two_factor_enabled")
    private boolean twoFactorEnabled =false;
    private String secret;


    public AppUser(String username, String password, String role,
                   String email, boolean twoFactorEnabled, String secret) {
        this.username = username;
        this.password = password;
        this.role = role;
        this.email = email;
        this.twoFactorEnabled = twoFactorEnabled;
        this.secret = secret;
    }

    @Override
    public String toString() {
        return "AppUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", role='" + role + '\'' +
                ", email='" + email + '\'' +
                ", twoFactorEnabled=" + twoFactorEnabled +
                ", secret='" + secret + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AppUser)) return false;
        AppUser appUser = (AppUser) o;
        return Objects.equals(username, appUser.username);
    }


    @Override
    public int hashCode(){
        return Objects.hash(username);
    }
}
