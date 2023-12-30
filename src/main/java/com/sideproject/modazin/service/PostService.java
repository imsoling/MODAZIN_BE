package com.sideproject.modazin.service;

import com.sideproject.modazin.dto.PostCreateDto;
import com.sideproject.modazin.entity.Post;
import com.sideproject.modazin.exception.InvalidRequestException;
import com.sideproject.modazin.exception.PostNotFoundException;
import com.sideproject.modazin.repository.ImageRepository;
import com.sideproject.modazin.repository.PostRepository;
import jakarta.transaction.Transactional;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class PostService {

    private final PostRepository postRepository;
    private final ImageRepository imageRepository;

    public PostService(PostRepository postRepository, ImageRepository imageRepository) {
        this.postRepository = postRepository;
        this.imageRepository = imageRepository;
    }

    // create
    @Transactional
    public void saveBy(String type, PostCreateDto req) {
        if (!type.equals(req.getContentType())) {
            throw new InvalidRequestException("Post type is not equal.");
        }

        Post saved = savePost(type, req);

        if (saved.getPostSeq() < 0) {
            throw new PostNotFoundException("Failed to create a post");
        }

        saveImage(req, saved);
    }

    private Post savePost(String type, PostCreateDto req) {
        Post post = Post.from(req);

        if ("M".equals(type)) {
            // if type is Map, set location
            post = Post.createLocation(req.getLongitude(), req.getLatitude());
        }
        return postRepository.save(post);
    }

    private void saveImage(PostCreateDto req, Post saved) {
        if (req.getImage().isEmpty()) {
            return;
        }

        // TODO image server 저장 로직 추가 예정

        imageRepository.save(saved.getPostSeq(), req.getImage());
    }

    public List<Post> findAllBy(String type) {
        List<Post> posts = postRepository.findByType(type);
        if (posts.isEmpty()) {
            throw new PostNotFoundException("Type: " + type + " is not found");
        }
        return posts;
    }

    // delete
    @Transactional
    public void deleteBy(String type, long postSeq) {
        // TODO 조건 상세 설정하기
        postRepository.deleteById(postSeq);
    }

}