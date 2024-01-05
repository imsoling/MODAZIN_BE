package com.sideproject.modazin.modajigi.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sideproject.modazin.controller.CommentController;
import com.sideproject.modazin.dto.CommentCreateDto;
import com.sideproject.modazin.service.CommentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest(CommentController.class)
class CommentControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CommentService commentService;

    @Test
    void createComment() throws Exception {
        CommentCreateDto dto = new CommentCreateDto();
        dto.setWriteUserSeq(1);
        dto.setWritePostSeq(1);
        dto.setContent("comment controller test");

        ObjectMapper objectMapper = new ObjectMapper();
        String dtoToJson = objectMapper.writeValueAsString(dto);

        mockMvc.perform(MockMvcRequestBuilders.post("/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dtoToJson))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

}