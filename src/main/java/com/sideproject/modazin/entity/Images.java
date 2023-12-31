package com.sideproject.modazin.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import jakarta.persistence.Id;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "images")
public class Images {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "image_seq")
    private Long imageSeq;

    @ManyToOne
    @JoinColumn(name = "post_seq", nullable = false)
    private Post postSeq;

    @Column(nullable = false)
    @Lob
    private String imageUrl;

}
