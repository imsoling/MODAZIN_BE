package com.sideproject.modazin.repository;

import com.sideproject.modazin.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommentRepository extends JpaRepository<Comment, Long> {

}
