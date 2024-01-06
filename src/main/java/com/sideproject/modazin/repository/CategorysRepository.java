package com.sideproject.modazin.repository;

import com.sideproject.modazin.entity.Categorys;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CategorysRepository extends JpaRepository<Categorys, Long> {

}
