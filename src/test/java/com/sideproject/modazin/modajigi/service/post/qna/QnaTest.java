//package com.sideproject.modazin.service.post.qna;
//
//import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import com.sideproject.modazin.controller.post.qna.QnaController;
//import com.sideproject.modazin.dto.post.qna.QnAPostReq;
//import com.sideproject.modazin.entity.post.qna.QnA;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
//import org.springframework.boot.test.mock.mockito.MockBean;
//import org.springframework.http.MediaType;
//import org.springframework.test.web.servlet.MockMvc;
//
//@WebMvcTest(QnaController.class)
//class QnaServiceTest {
//    @Autowired
//    private MockMvc mockMvc;
//
//    @MockBean
//    private QnaService qnaService;
//
//    @Test
//    void qnaSave() throws Exception {
//        QnAPostReq qnAPostReq = new QnAPostReq();
//        qnAPostReq.setTitle("qna save title test");
//        qnAPostReq.setWriteUserSeq(1);
//        qnAPostReq.setContent("qna save content test");
//        qnAPostReq.setImages("qna save images test");
//        qnAPostReq.setHashtag("qna save hashtag test");
//
//        QnA qna = new QnA();
//        qna.createQnA(qnAPostReq);
//
//        mockMvc.perform(post("/post/qna/save"))
//                .contentType(MediaType.APPLICATION_JSON)
//                .content(new ObjectMapper().writeValueAsString(postDTO)))
//
//    }
//}
