package com.sideproject.modazin.entity.post.qna;

//import com.sideproject.modazin.dto.post.qna.QnAPostReq;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name= "qna")
public class QnA {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="qna_seq", nullable = false)
    private Long qnaSeq;

    @Column(name="content_type", nullable = false)
    private String contentType;

    @Column(name="category_seq", nullable = false)
    private int categorySeq;

    private String hashtag;

    @Column(nullable = false)
    private String title;

    @Column(name="write_user_seq",  nullable = false)
    private int writeUserSeq;

    @Column(nullable = false)
    private String content;

    @Column(name="view_cont")
    private int viewCnt;

    @Column(name="like_cnt")
    private int likeCnt;

    @Column(name="report_cnt")
    private int reportCnt;

    @Column(name="created_at", nullable = false)
    private Date createdAt;

    @Column(name="updated_at", nullable = false)
    private Date updatedAt;

    @Column(nullable = false)
    private String status;

}
