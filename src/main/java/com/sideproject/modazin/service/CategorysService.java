package com.sideproject.modazin.service;

import com.sideproject.modazin.dto.CategorysDto;
import com.sideproject.modazin.entity.Categorys;
import com.sideproject.modazin.exception.NotFoundException;
import com.sideproject.modazin.repository.CategorysRepository;
import jakarta.transaction.Transactional;
import java.util.List;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CategorysService {
    private final CategorysRepository categorysRepository;

    @Transactional
    public void create(CategorysDto req) {
        Categorys categorys = Categorys.createFrom(req);
        Categorys saved = categorysRepository.save(categorys);
        if (saved.getCategorySeq() < 0) {
            throw new NotFoundException("Failed to create a category");
        }
    }

    public List<Categorys> findAll() {
        List<Categorys> categorys = categorysRepository.findAll();
        if (categorys.isEmpty()) {
            throw new NotFoundException("Failed to find a category");
        }
        return categorys;
    }

    public Categorys update(Long categorySeq, CategorysDto req) {
        Categorys category = findCategoryById(categorySeq);
        category.updateFrom(req);
        return categorysRepository.save(category);
    }

    public void delete(long categorySeq) {
        Categorys category = findCategoryById(categorySeq);
        // hyunzin 관리자인지 권한 체크
        categorysRepository.deleteById(categorySeq);

    }

    private Categorys findCategoryById(long categorySeq) {
        return categorysRepository.findById(categorySeq).orElseThrow(() -> new NotFoundException("NOT FOUND"));
    }
}
