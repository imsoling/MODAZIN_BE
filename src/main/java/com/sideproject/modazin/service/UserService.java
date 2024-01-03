package com.sideproject.modazin.service;

import com.sideproject.modazin.dto.UserSignUpDto;
import com.sideproject.modazin.entity.User;
import com.sideproject.modazin.entity.UserLog;
import com.sideproject.modazin.repository.UserLogRepository;
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
    private final UserLogRepository userLogRepository;
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


    // user 위치정보 저장
    // TODO 마이페이지에서도 사용할 수 있도록 추가
    public void saveUserLog(UserSignUpDto userSignUpDto) {
        if (userSignUpDto.getLongitude() == null || userSignUpDto.getLatitude() == null ) {
            return;
        }

        UserLog userLog = UserLog.saveUserLog(userSignUpDto.getUserSeq()
                                    , userSignUpDto.getLongitude()
                                    , userSignUpDto.getLatitude());

        userLogRepository.save(userLog);
    }
}
