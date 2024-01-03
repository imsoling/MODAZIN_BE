package com.sideproject.modazin.entity;

import jakarta.persistence.*;
import lombok.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name= "user_log")
public class UserLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_seq", nullable = false)
    private Long logSeq;

    @Column(name = "user_seq", nullable = false)
    private Long userSeq;

    @Column(nullable = false)
    private BigDecimal longitude;

    @Column(nullable = false)
    private BigDecimal latitude;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public static UserLog saveUserLog(Long userSeq, BigDecimal longitude, BigDecimal latitude) {
        return UserLog.builder()
                .userSeq(userSeq)
                .longitude(longitude)
                .latitude(latitude)
                .build();
    }

}
