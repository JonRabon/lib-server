package com.coderepojon.dbPostgres.services;

import com.coderepojon.dbPostgres.domain.dto.CreateUserRequestDto;
import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import org.springframework.web.multipart.MultipartFile;

public interface UserAccountService {

    UserProfileDto createUser(CreateUserRequestDto request, MultipartFile avatar);

}
