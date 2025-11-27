package com.coderepojon.dbPostgres.mappers;

import com.coderepojon.dbPostgres.domain.dto.AuthorDto;
import com.coderepojon.dbPostgres.domain.entities.AuthorEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface AuthorMapper extends EntityMapper<AuthorEntity, AuthorDto> {

    @Override
    AuthorDto mapTo(AuthorEntity entity);

    @Override
    AuthorEntity mapFrom(AuthorDto dto);
}
