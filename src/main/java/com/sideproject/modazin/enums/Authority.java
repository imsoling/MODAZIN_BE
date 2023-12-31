package com.sideproject.modazin.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Authority {
    USER("USER"),
    ADMIN("ADMIN");

    private final String authority;
}



