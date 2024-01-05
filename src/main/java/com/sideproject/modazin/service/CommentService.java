package com.sideproject.modazin.service;

import com.sideproject.modazin.dto.CommentCreateDto;
import com.sideproject.modazin.entity.Comment;
import com.sideproject.modazin.entity.Post;
import com.sideproject.modazin.entity.User;
import com.sideproject.modazin.repository.CommentRepository;
import com.sideproject.modazin.repository.PostRepository;
import com.sideproject.modazin.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class CommentService {
    private PostRepository postRepository;
    private UserRepository userRepository;
    private CommentRepository commentRepository;
    public void create(CommentCreateDto dto) {
        User user = userRepository.findById(dto.getWriteUserSeq())
                .orElseThrow(() -> new RuntimeException("User not found"));
        Post post = postRepository.findById(dto.getWritePostSeq())
                .orElseThrow(() -> new RuntimeException("Post not found"));

        Comment comment = Comment.from(dto, user, post);
        commentRepository.save(comment);
    }
}
