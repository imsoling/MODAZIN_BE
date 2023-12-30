//package com.sideproject.modazin.modajigi.controller;
//
//import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
//import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
//import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
//import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
//
//import com.sideproject.modazin.controller.post.qna.QnaController;
//import com.sideproject.modazin.restdocs.RestDocsTest;
//import com.sideproject.modazin.restdocs.config.RestDocsConfig;
//import java.io.File;
//import java.io.IOException;
//import java.nio.file.Files;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
//import org.springframework.http.MediaType;
//import org.springframework.restdocs.payload.JsonFieldType;
//import org.springframework.test.web.servlet.MockMvc;
//import org.springframework.test.web.servlet.ResultActions;
//import org.springframework.util.ResourceUtils;
//
//@WebMvcTest(QnaController.class)
//public class QnaControllerTest extends RestDocsTest {
//
//    @Autowired
//    private MockMvc mockMvc;
//
//    @Autowired
//    private RestDocsConfig restDocs;
//
//    private String readJsonFile(String path) throws IOException {
//        File file = ResourceUtils.getFile(path);
//        return new String(Files.readAllBytes(file.toPath()));
//    }
//
//    @Test
//    void saveQna() throws Exception {
//        // given
//        String jsonContent = readJsonFile("classpath:saveQnaReq.json");
//
//        // when
//        ResultActions result = mockMvc.perform(post("/post/qna/save")
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .accept(MediaType.APPLICATION_JSON)
//                        .content(jsonContent))
//                .andExpect(status().isOk());
//
//        // docs
//        result.andDo(
//                restDocs.document(
//                        requestFields(
//                                fieldWithPath("contentType").type(JsonFieldType.STRING).description("타입"),
//                                fieldWithPath("categorySeq").type(JsonFieldType.STRING).description("카테고리 시퀀스"),
//                                fieldWithPath("title").type(JsonFieldType.STRING).description("제목"),
//                                fieldWithPath("writeUserSeq").type(JsonFieldType.STRING).description("작성자 시퀀스"),
//                                fieldWithPath("content").type(JsonFieldType.STRING).description("내용"),
//                                fieldWithPath("images").type(JsonFieldType.STRING).description("이미지"),
//                                fieldWithPath("hashtag").type(JsonFieldType.STRING).description("해시태그"),
//                                fieldWithPath("status").type(JsonFieldType.STRING).description("상태"),
//                                fieldWithPath("createAt").type(JsonFieldType.STRING).description("생성 날짜")
//                        ),
//                        defaultCommonResponse("QnA 게시글 CREATE")
//                ));
//    }
//}