//package com.sideproject.modazin.service.user;
//
//import com.sideproject.modazin.enums.Authority;
//import com.sideproject.modazin.entity.User;
//import com.sideproject.modazin.service.UserService;
//import jakarta.transaction.Transactional;
//import org.junit.jupiter.api.Disabled;
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.test.annotation.Rollback;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//@SpringBootTest
//@Transactional
//public class UserServiceTest {
//
//    @Autowired
//    UserService userService;
//
//    @Autowired
//    PasswordEncoder passwordEncoder;
//
//    @Test
//    @Disabled("회원가입 테스트")
//    @Rollback(value = false)
//    public void signUpUserTest() {
//        User user = User.builder()
//                .email("eumsoli@gmial.com")
//                .nickName("하이솔이")
//                .password("1216")
//                .longitude(12)
//                .latitude(16)
////                .locationCreatedAt(new Date())
//                .phoneNumber("010-6526-1612")
//                .profile("url/test")
//                .status("Y")
////                .badge()
////                .createdAt(new Date())
////                .deleteAt(new Date())
//                .authority(Authority.USER)
//                .build();
//        User signUpUser = userService.signUpUser(user);
//
//        assertEquals(user.getEmail(),signUpUser.getEmail());
//
//
//    }
//
//}
