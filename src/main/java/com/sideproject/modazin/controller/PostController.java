package com.sideproject.modazin.controller;

import com.sideproject.modazin.dto.PostCreateDto;
import com.sideproject.modazin.entity.Post;
import com.sideproject.modazin.exception.InvalidRequestException;
import com.sideproject.modazin.service.post.PostService;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/post/content-type/{contentType}")
public class PostController {

    private final PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

    // create
    @PostMapping("/save")
    public ResponseEntity<String> save(@PathVariable("contentType") String type, @RequestBody PostCreateDto req) {
        try {
            postService.saveBy(type, req);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (InvalidRequestException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // find all
    @GetMapping("/find")
    public ResponseEntity<List<Post>> findAll(@PathVariable("contentType") String type) {
        List<Post> posts = postService.findAllBy(type);

        return new ResponseEntity<>(posts, HttpStatus.OK);
    }


    // delete
    @DeleteMapping("/{postSeq}")
    public ResponseEntity<?> deletePost(
            @PathVariable String contentType,
            @PathVariable int postSeq) {
        postService.deleteBy(contentType, postSeq);
        return ResponseEntity.ok().build();
    }
}
