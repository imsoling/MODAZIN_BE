package com.sideproject.modazin.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

@Entity
@Table(name = "comment")
public class Comment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "comment_seq")
    private int commentSeq;

    @Column(name = "content_type", nullable = false)
    private String contentType = "C";

    @ManyToOne
    @JoinColumn(name = "write_user_seq", nullable = false)
    private User writeUserSeq;

    @Column(name = "post_Type", nullable = false)
    private String postType;

    @ManyToOne
    @JoinColumn(name = "write_post_seq", nullable = false)
    private Post writePostSeq;

    @ManyToOne
    @JoinColumn(name = "write_comment_seq")
    private Comment writeCommentSeq;

    @Column(name = "content", nullable = false, length = 500)
    private String content;

    @Column(name = "like_cnt")
    private Integer likeCnt = 0;

    @Column(name = "report_cnt")
    private Integer reportCnt = 0;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "status", nullable = false)
    private String status = "Y";
}
