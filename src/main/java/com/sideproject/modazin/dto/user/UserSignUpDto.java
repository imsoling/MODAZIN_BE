package com.sideproject.modazin.dto.user;

import com.sideproject.modazin.enums.user.Authority;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSignUpDto {
    private Long userSeq;
    private String email;
    private String nickName;
    private String password;
    private BigDecimal longitude;
    private BigDecimal latitude;
    private LocalDateTime locationCreatedAt;
    private String phoneNumber;
    private String profile;
    private String status;
    private String badge;
    private LocalDateTime createAt;
    private LocalDateTime deleteAt;

    @Enumerated(EnumType.STRING)
    private Authority authority ;

}
