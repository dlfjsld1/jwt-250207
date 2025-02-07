package com.example.jwt;

import com.example.jwt.domain.member.member.service.AuthTokenService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Transactional
public class AuthTokenServiceTest {

    @Autowired
    private AuthTokenService authTokenService;

    @Test
    @DisplayName("AuthTokenService 생성")
    void init() {
        assertThat(authTokenService).isNotNull();
    }
}
