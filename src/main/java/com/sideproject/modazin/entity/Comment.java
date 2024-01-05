package com.sideproject.modazin.entity;

import com.sideproject.modazin.dto.CommentCreateDto;
import com.sideproject.modazin.dto.CommentUpdateDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "comment")
public class Comment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "comment_seq")
    private long commentSeq;

    @Column(nullable = false, columnDefinition = "CHAR(1) DEFAULT 'C'")
    private String contentType;

    @ManyToOne
    @JoinColumn(name = "write_user_seq", nullable = false)
    private User writeUserSeq;

    @ManyToOne
    @JoinColumn(name = "write_post_seq", nullable = false)
    private Post writePostSeq;

    @ManyToOne
    @JoinColumn(name = "write_comment_seq")
    private Comment writeCommentSeq;

    @Setter
    @Column(name = "content", nullable = false, length = 500)
    private String content;

    @Builder.Default
    @Column(name = "like_cnt")
    private int likeCnt = 0;

    @Builder.Default
    @Column(name = "report_cnt")
    private int reportCnt = 0;

    @Builder.Default
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Builder.Default
    @Column(name = "status")
    private String status = "Y";

    public static Comment from(CommentCreateDto dto, User user, Post post) {
        return Comment.builder()
                .contentType("C")
                .writeUserSeq(user)
                .writePostSeq(post)
                .content(dto.getContent())
                .build();
    }
}
