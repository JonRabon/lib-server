package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;

public interface UserAccountService {

    UserProfileDto createUser(CreateUserRequestDto request);

}
