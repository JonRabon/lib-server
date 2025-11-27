package com.coderepojon.dbPostgres.mappers;

import com.coderepojon.dbPostgres.domain.dto.BookDto;
import com.coderepojon.dbPostgres.domain.entities.BookEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface BookMapper extends EntityMapper<BookEntity, BookDto> {

    @Override
    BookDto mapTo(BookEntity entity);

    @Override
    BookEntity mapFrom(BookDto dto);
}
