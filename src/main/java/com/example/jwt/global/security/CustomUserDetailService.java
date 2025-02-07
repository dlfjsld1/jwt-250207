package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

//이 코드의 역할은 스프링 시큐리티가 제공하는 UserDetailsService 인터페이스를 구현하여,
// 사용자 정보를 데이터베이스에서 가져오는 로직을 정의하는 것.
// CustomUserDetailService의 역할은 사용자 이름(username)을 기반으로
// 데이터베이스에서 사용자 정보를 조회하고,
// 그 정보를 스프링 시큐리티가 이해할 수 있는 UserDetails 객체로 변환하여 반환하는 것.
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));


        // username, password, authorities
        return new User(member.getUsername(), member.getPassword(), List.of());
    }
}
