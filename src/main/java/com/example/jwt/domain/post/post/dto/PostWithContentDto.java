package com.example.jwt.domain.post.post.dto;

import com.example.jwt.domain.post.post.entity.Post;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class PostWithContentDto {

    private long id;
    private LocalDateTime createdDate;
    private LocalDateTime modifiedDate;
    private String title;
    private String content;
    private boolean published;
    private boolean listed;
    private long authorId;
    private String authorName;

    public PostWithContentDto(Post post) {
        this.id = post.getId();
        this.createdDate = post.getCreatedDate();
        this.modifiedDate = post.getModifiedDate();
        this.title = post.getTitle();
        this.content = post.getContent();
        this.published = post.isPublished();
        this.listed = post.isListed();
        this.authorId = post.getAuthor().getId();
        this.authorName = post.getAuthor().getNickname();
    }
}
