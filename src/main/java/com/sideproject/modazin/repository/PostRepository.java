package com.sideproject.modazin.repository;

import com.sideproject.modazin.entity.Post;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PostRepository extends JpaRepository<Post, Long> {
    @Query("SELECT p FROM Post p WHERE p.contentType = :type")
    List<Post> findByType(@Param("type") String type);
}
