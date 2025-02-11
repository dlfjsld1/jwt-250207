package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final MemberService memberService;
    private final Rq rq;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");

        //헤더에 로그인 정보가 없으면
        if (authorizationHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        //헤더에 로그인 정보가 이상하다면
        if(!authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authToken = authorizationHeader.substring("Bearer ".length());

        String[] tokenBits = authToken.split(" ", 2);

        if(tokenBits.length < 2) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = tokenBits[0];
        String accessToken = tokenBits[1];

        //기존 apiKey 방식 인증
//        Optional<Member> opMember = memberService.findByApiKey(apiKey);

        // select * from member where api_key = 'user1;

        //accessToken 인증 방식
        Optional<Member> opAccMember = memberService.getMemberByAccessToken(accessToken);

        //로그인 정보와 DB가 맞지 않다면
        if(opAccMember.isEmpty()) {

            //재발급
            Optional<Member> opApiMember = memberService.findByApiKey(apiKey);

            if(opApiMember.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            String newAuthToken = memberService.getAuthToken(opApiMember.get());

            response.addHeader("Authorization", "Bearer " + newAuthToken);

            Member actor = opApiMember.get();
            rq.setLogin(actor);

            filterChain.doFilter(request, response);
            return;
        }

        Member actor = opAccMember.get();
        //rq.setLogin은 security의 SecurityContextHolder에 유저 정보 저장(세션 방식) = 로그인
        rq.setLogin(actor);

        //doFilter의 역할은 다음으로 넘어가라는 것. 다음은 다음 필터가 될수도, 그냥 넘어가는 걸수도 있음
        filterChain.doFilter(request, response);
    }
}
