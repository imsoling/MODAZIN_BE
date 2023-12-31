package com.sideproject.modazin.service;

import com.sideproject.modazin.dto.UserSignUpDto;
import com.sideproject.modazin.entity.User;
import com.sideproject.modazin.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public User signUpUser(UserSignUpDto userSignUpDto) {
        validateDuplicateUser(userSignUpDto);

        // 비밀번호 암호화
        String encodedPassword = bCryptPasswordEncoder.encode(userSignUpDto.getPassword());

        User user = User.createUser(userSignUpDto, bCryptPasswordEncoder);

        return userRepository.save(user);
    }
    private void validateDuplicateUser(UserSignUpDto userSignUpDto) {
        if (userRepository.existsByEmail(userSignUpDto.getEmail())) {
            throw new IllegalStateException("이미 가입된 이메일입니다.");
        }

        if (userRepository.existsByNickName(userSignUpDto.getNickName())) {
            throw new IllegalStateException("이미 사용 중인 닉네임입니다.");
        }
    }
}
