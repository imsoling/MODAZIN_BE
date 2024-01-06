package com.sideproject.modazin.entity;

import com.sideproject.modazin.dto.CategorysDto;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "categorys")
public class Categorys {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "category_seq", nullable = false)
    private Long categorySeq;

    @Column(name = "content_type", nullable = false)
    private String contentType;

    @Column(name = "category", nullable = false, length = 200)
    private String category;

    public static Categorys createFrom(CategorysDto dto) {
        return com.sideproject.modazin.entity.Categorys.builder()
                .contentType(dto.getContentType())
                .category(dto.getCategory())
                .build();
    }

    public void updateFrom(CategorysDto dto) {
        this.contentType = dto.getContentType();
        this.category = dto.getCategory();
    }

}