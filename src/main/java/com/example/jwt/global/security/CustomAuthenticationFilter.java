package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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

    private final Rq rq;
    private final MemberService memberService;

    private boolean isAuthorizationHeader(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        //헤더에 로그인 정보가 없으면
        if(authorizationHeader == null) {
            return false;
        }

        //헤더에 로그인 정보가 이상하다면
        if(!authorizationHeader.startsWith("Bearer ")) {
            return false;
        }

        return true;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(isAuthorizationHeader(request)) {

            String authorizationHeader = request.getHeader("Authorization");
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

            //accessToken에 문제가 있는 경우(ex - 만료됨)

            if(opAccMember.isEmpty()) {

                // 재발급
                Optional<Member> opApiMember = memberService.findByApiKey(apiKey);

                if(opApiMember.isEmpty()) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String newAccessToken = memberService.genAccessToken(opApiMember.get());
                response.addHeader("Authorization", "Bearer " + newAccessToken);


                Member actor = opApiMember.get();
                rq.setLogin(actor);

                filterChain.doFilter(request, response);
                return;
            }

            Member actor = opAccMember.get();
            rq.setLogin(actor);

            filterChain.doFilter(request, response);
        } else {

            Cookie[] cookies = request.getCookies();
            if(cookies == null) {
                filterChain.doFilter(request, response);
                return;
            }

            for(Cookie cookie : cookies) {
                if(cookie.getName().equals("accessToken")) {
                    String accessToken = cookie.getValue();

                    Optional<Member> opMember = memberService.getMemberByAccessToken(accessToken);

                    if(opMember.isEmpty()) {
                        filterChain.doFilter(request, response);
                        return;
                    }

                    Member actor = opMember.get();
                    rq.setLogin(actor);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}