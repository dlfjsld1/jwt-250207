package com.example.jwt.domain.member.member.service;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final AuthTokenService authTokenService;

    public Member join(String username, String password, String nickname) {

        UUID uuid = UUID.randomUUID();
        String uuidString = uuid.toString();

        Member member = Member.builder()
                .username(username)
                .password(password)
                .apiKey(username)
                .nickname(nickname)
                .build();

        return memberRepository.save(member);
    }

    public long count() {
        return memberRepository.count();
    }

    public Optional<Member> findByUsername(String username) {
        return memberRepository.findByUsername(username);
    }

    public Optional<Member> findById(long id) {
        return memberRepository.findById(id);
    }

    public Optional<Member> findByApiKey(String apiKey) {
        return memberRepository.findByApiKey(apiKey);
    }

    public String getAuthToken(Member member) {
        return member.getApiKey() + " " + authTokenService.genAccessToken(member);
    }

    public Optional<Member> getMemberByAccessToken(String accessToken) {
        //accessToken을 파싱해서 회원 id를 가져와 Member를 리턴한다.
        Map<String, Object> payload = authTokenService.getPayload(accessToken);

        if(payload == null) {
            return Optional.empty();
        }

        long id = (long)payload.get("id");
        String username = (String)payload.get("username");

        return Optional.of(
                Member.builder()
                .id(id)
                .username(username)
                .build()
        );

//        return memberRepository.findById(id);
    }

    public String genAccessToken(Member member) {
        return authTokenService.genAccessToken(member);
    }
}