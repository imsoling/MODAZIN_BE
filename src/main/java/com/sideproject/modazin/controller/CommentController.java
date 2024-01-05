package com.sideproject.modazin.controller;

import com.sideproject.modazin.dto.CommentCreateDto;
import com.sideproject.modazin.service.CommentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/comment")
public class CommentController {
    private CommentService commentService;

    @PostMapping("/create")
    public ResponseEntity<String> create(@RequestBody CommentCreateDto req) {
        commentService.create(req);
        return new ResponseEntity<>(HttpStatus.OK);
    }

}
