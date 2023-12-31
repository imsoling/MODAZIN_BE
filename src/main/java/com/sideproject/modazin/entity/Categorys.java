package com.sideproject.modazin.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
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
}