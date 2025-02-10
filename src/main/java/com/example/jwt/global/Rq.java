package com.example.jwt.global;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.exception.ServiceException;
import com.example.jwt.global.security.SecurityUser;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

import java.util.List;

// Request, Response, Session, Cookie, Header
@Component
@RequiredArgsConstructor
//매 요청마다 생성되고 사라지게 하는 어노테이션
@RequestScope
public class Rq {

    private final HttpServletRequest request;
    private final MemberService memberService;

//    public Member getAuthenticatedActor() {
//
//        String authorizationValue = request.getHeader("Authorization");
//        String apiKey = authorizationValue.substring("Bearer ".length());
//        Optional<Member> opActor = memberService.findByApiKey(apiKey);
//
//        if(opActor.isEmpty()) {
//            throw new ServiceException("401-1", "잘못된 인증키입니다.");
//        }
//
//        return opActor.get();
//    }

    public void setLogin(Member actor) {
        //유저 정보 생성
        UserDetails user = new SecurityUser(actor.getId(), actor.getUsername(), actor.getPassword(), List.of());

        //인증 정보 저장소. security는 여기를 확인해 해당 유저가 존재하면 로그인 한 것으로 인식.
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
        );
    }

    public Member getActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null) {
            throw new ServiceException("402-2", "로그인이 필요합니다.");
        }

        //인증정보 가져오기
        Object principal = authentication.getPrincipal();

        if(!(principal instanceof SecurityUser)) {
            throw new ServiceException("401-3", "잘못된 인증 정보입니다.");
        }

        SecurityUser user = (SecurityUser) principal;

        return Member.builder()
                .id(user.getId())
                .username(user.getUsername())
                .build();
    }
}
