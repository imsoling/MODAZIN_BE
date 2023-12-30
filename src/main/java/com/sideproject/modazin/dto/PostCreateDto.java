package com.sideproject.modazin.dto;

import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PostCreateDto {
    private String contentType;
    private Long categorySeq;
    private String title;
    private Long writeUserSeq;
    private String content;
    private String image;
    private BigDecimal longitude; // only type: M
    private BigDecimal latitude; // only type: M
    private String hashtag;
    private String status;
}