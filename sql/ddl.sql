# drop table reports;
# drop table comment;
# drop table followingblock;
# drop table likes;
# drop table scraps;
# drop table scrap_folder;
# drop table images;
# drop table post;
# drop table categorys;
# drop table user_log;
# drop table user;

-- DB 확인
show databases ;

-- DB 생성
create database modazin default character set utf8;

-- DB 사용
use modazin;

-- USER 생성
create user modazin@'%' identified by 'modazin0816';

-- 권한 부여
grant all privileges on modazin.* to modazin@'%';

-- DB 반영
flush privileges;

-- 권한확인
show grants for modazin@'%';

-- 회원
create table if not exists user
(
    user_seq            int auto_increment
    primary key,
    email               varchar(255)                          not null,
    nick_name           varchar(50)                           not null,
    password            varchar(255)                          not null,
    longitude           decimal(10, 6)                        not null,
    latitude            decimal(10, 6)                        not null,
    location_created_at datetime    default CURRENT_TIMESTAMP not null,
    phone_number        varchar(20)                           null,
    profile             text                                  null,
    status              char        default 'Y'               not null,
    badge               varchar(50)                           null,
    created_at          datetime    default CURRENT_TIMESTAMP not null,
    deleted_at          datetime                              null,
    authority           varchar(20) default 'USER'            not null
    );

-- 회원 위치 기록
create table if not exists user_log
(
    log_seq    int auto_increment
    primary key,
    user_seq   int                                not null,
    longitude  decimal(10, 6)                     not null,
    latitude   decimal(10, 6)                     not null,
    created_at datetime default CURRENT_TIMESTAMP not null,
    constraint user_log_user_seq_fk
    foreign key (user_seq) references user (user_seq)
    );

-- 카테고리
create table if not exists categorys
(
    category_seq int auto_increment
    primary key,
    content_type char         not null,
    category     varchar(200) not null
    );

-- 게시글
create table if not exists post
(
    post_seq        int auto_increment
    primary key,
    content_type   char                               not null,
    category_seq   int                                not null,
    title          varchar(300)                       not null,
    write_user_seq int                                not null,
    content        text                               not null,
    longitude      decimal(10, 6)                     null,
    latitude       decimal(10, 6)                     null,
    hashtag        text                               null,
    view_cnt       int      default 0                 null,
    like_cnt       int      default 0                 null,
    report_cnt     int      default 0                 null,
    created_at     datetime default CURRENT_TIMESTAMP not null,
    updated_at     datetime default CURRENT_TIMESTAMP not null,
    status         char     default 'Y'               not null,
    constraint post_category_seq_fk
    foreign key (category_seq) references categorys (category_seq),
    constraint post_user_seq_fk
    foreign key (write_user_seq) references user (user_seq)
    );

-- 스크랩 폴더
create table if not exists scrap_folder
(
    folder_seq  int auto_increment
    primary key,
    folder_name varchar(300)     not null,
    user_seq    int              not null,
    status      char default 'Y' not null,
    constraint scrap_folder_user_seq_fk
    foreign key (user_seq) references user (user_seq)
    );

-- 스크랩
create table if not exists scraps
(
    scrap_seq    int  auto_increment,
    user_seq     int  not null,
    post_seq     int  not null,
    folder_seq   int  null,
    primary key (scrap_seq, user_seq),
    constraint scraps_user_seq_fk
    foreign key (user_seq) references user (user_seq),
    constraint scraps_post_seq_fk
    foreign key (post_seq) references post (post_seq),
    constraint scraps_folder_seq_fk
    foreign key (folder_seq) references scrap_folder (folder_seq)
    );

-- 좋아요
create table if not exists likes
(
    like_seq     int auto_increment,
    user_seq     int  not null,
    post_seq     int  not null,
    status       char default 'Y' not null,
    primary key (like_seq, user_seq),
    constraint likes_user_seq_fk
    foreign key (user_seq) references user (user_seq),
    constraint likes_post_seq_fk
    foreign key (post_seq) references post (post_seq)
    );

-- 팔로잉 & 블락
create table if not exists followingblock
(
    user_seq    int  not null,
    fb_type     char not null,
    fb_user_seq int  not null,
    primary key (user_seq, fb_user_seq),
    constraint followingblock_user_seq_fk
    foreign key (user_seq) references user (user_seq),
    constraint followingblock_fb_user_seq_fk
    foreign key (fb_user_seq) references user (user_seq)
    );

-- 댓글
create table if not exists comment
(
    comment_seq       int auto_increment
    primary key,
    content_type      char     default 'C'               not null,
    write_user_seq    int                                not null,
    post_type         char                               not null,
    write_post_seq    int                                not null,
    write_comment_seq int                                null,
    content           varchar(500)                       not null,
    like_cnt          int      default 0                 null,
    report_cnt        int      default 0                 null,
    created_at        datetime default CURRENT_TIMESTAMP not null,
    updated_at        datetime default CURRENT_TIMESTAMP not null,
    status            char     default 'Y'               not null,
    constraint comment_user_seq_fk
    foreign key (write_user_seq) references user (user_seq),
    constraint comment_post_seq_fk
    foreign key (write_post_seq) references post (post_seq),
    constraint comment_comment_seq_fk
    foreign key (write_comment_seq) references comment (comment_seq)
    );

-- 신고
create table if not exists reports
(
    report_seq   int auto_increment
    primary key,
    content_type char                               not null,
    user_seq     int                                not null,
    post_seq     int                                null,
    comment_seq  int                                null,
    content      varchar(500)                       not null,
    created_at   datetime default CURRENT_TIMESTAMP not null,
    constraint reports_user_seq_fk
    foreign key (user_seq) references user (user_seq),
    constraint reports_post_seq_fk
    foreign key (post_seq) references post (post_seq),
    constraint reports_comment_seq_fk
    foreign key (comment_seq) references comment (comment_seq)
    );


