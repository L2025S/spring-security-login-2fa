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


    @NotBlank(message="Username is required.")
    @Size(min=3, max = 50, message="Username must be between 3 and 50 characters.")
    @Pattern(regexp="^[a-zA-Z0-9._-]+$",message = "Username can only contain letters, numbers, dots, underscores and hyphens")
    @Column(unique=true, nullable=false, length =255)
    private String username;


    @NotBlank(message ="Password is required.")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters.")
    @Pattern(
            regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$",
            message="Password must contain at least one digit, one lowercase, one uppercase, " +
                    "one special character, and no whitespace"
    )
    @Column(nullable=false, length = 1000)
    private String password;

    private String role;

    @Email(message= "Email should be valid")
    @NotBlank(message="Email is required.")
    @Size(max= 100, message = "Email must be less than 100 characters.")
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
