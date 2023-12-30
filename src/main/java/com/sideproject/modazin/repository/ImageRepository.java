package com.sideproject.modazin.repository;

import com.sideproject.modazin.entity.Post;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ImageRepository extends JpaRepository<Post, Long> {

    @Modifying
    @Query(value = "INSERT INTO images (post_seq, image_url) VALUES (:post_seq, :url)", nativeQuery = true)
    void save(@Param("post_seq") Long postSeq, @Param("url") String url);

}
