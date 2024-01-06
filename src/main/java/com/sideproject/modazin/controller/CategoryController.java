package com.sideproject.modazin.controller;

import com.sideproject.modazin.dto.CategorysDto;
import com.sideproject.modazin.entity.Categorys;
import com.sideproject.modazin.exception.NotFoundException;
import com.sideproject.modazin.service.CategorysService;
import java.util.List;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;


@AllArgsConstructor
@RestController
@RequestMapping("/category")
public class CategoryController {

    private final CategorysService categorysService;

    @PostMapping("/create")
    public ResponseEntity<String> create(@RequestBody CategorysDto req) {
        try {
            categorysService.create(req);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (NotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", e);
        }
    }

    @GetMapping("/findAll")
    public ResponseEntity<List<Categorys>> findAll() {
        try {
            List<Categorys> categorys = categorysService.findAll();
            return new ResponseEntity<>(categorys, HttpStatus.OK);
        } catch (NotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", e);
        }
    }

    @PostMapping("/update/{categorySeq}")
    public ResponseEntity<Categorys> update(@PathVariable("categorySeq") long categorySeq, @RequestBody CategorysDto req) {
        try {
            Categorys result = categorysService.update(categorySeq, req);
            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch (NotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", e);
        }
    }

    @DeleteMapping("/delete/{categorySeq}")
    public ResponseEntity<Categorys> delete(@PathVariable("categorySeq") long categorySeq) {
        try {
            categorysService.delete(categorySeq);
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (NotFoundException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", e);
        }
    }
}
