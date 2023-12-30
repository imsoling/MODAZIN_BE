package com.sideproject.modazin.entity;

import com.sideproject.modazin.dto.PostCreateDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Temporal;
import jakarta.persistence.TemporalType;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "post")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "post_seq")
    private Long postSeq;

    @Column(name = "content_type", nullable = false)
    private String contentType;

    @Column(name = "category_seq", nullable = false)
    private Long categorySeq;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "write_user_seq", nullable = false)
    private Long writeUserSeq;

    @Column(name = "content", nullable = false)
    private String content;

    @Column(name = "longitude", precision = 10, scale = 6)
    private BigDecimal longitude;

    @Column(name = "latitude", precision = 10, scale = 6)
    private BigDecimal latitude;

    @Column(name = "hashtag")
    private String hashtag;

    @Column(name = "view_cnt")
    private int viewCnt = 0;

    @Column(name = "like_cnt")
    private int likeCnt = 0;

    @Column(name = "report_cnt")
    private int reportCnt = 0;

    @Column(name = "created_at", nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime updatedAt;

    @Column(name = "status", nullable = false)
    @ColumnDefault("'Y'")
    private String status;

    public static Post from(PostCreateDto dto) {
        return Post.builder()
                .contentType(dto.getContentType())
                .categorySeq(dto.getCategorySeq())
                .title(dto.getTitle())
                .writeUserSeq(dto.getWriteUserSeq())
                .content(dto.getContent())
                .hashtag(dto.getHashtag())
                .createdAt(LocalDateTime.now())
                .status(dto.getStatus())
                .build();
    }

    public static Post createLocation(BigDecimal longitude, BigDecimal latitude) {
        return Post.builder()
                .longitude(longitude)
                .latitude(latitude)
                .build();
    }
}