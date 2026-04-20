package se.iths.lw.springsecuritylogin2fa.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserRegistrationDto {


    @NotBlank(message="Username is required.")
    @Size(min=3, max = 50, message="Username must be between 3 and 50 characters.")
    @Pattern(regexp="^[a-zA-Z0-9._-]+$",message = "Username can only contain letters, numbers, dots, underscores and hyphens")
    private String username;


    @NotBlank(message ="Password is required.")
    @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters.")
    @Pattern(
            regexp="^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$",
            message="Password must contain at least one digit, one lowercase, one uppercase, " +
                    "one special character, and no whitespace"
    )
    private String password;

    private String role;

    @Email(message= "Email should be valid")
    @NotBlank(message="Email is required.")
    @Size(max= 100, message = "Email must be less than 100 characters.")
    private String email;

    private boolean twoFactorEnabled =false;
}
