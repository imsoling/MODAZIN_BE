package com.sideproject.modazin.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sideproject.modazin.dto.CategorysDto;
import com.sideproject.modazin.service.CategorysService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest(CategoryController.class)
class CategoryControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    CategorysService categorysService;
    @Test
    void create() throws Exception {
        // given
        CategorysDto dto = new CategorysDto();
        dto.setCategory("T");
        dto.setContentType("controller test");

        // when
        ObjectMapper objectMapper = new ObjectMapper();
        mockMvc.perform(MockMvcRequestBuilders.post("/category/create")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(dto)))
                // then
                .andExpect(MockMvcResultMatchers.status().isOk());
    }
}