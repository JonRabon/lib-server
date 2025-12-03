package com.coderepojon.dbPostgres.mappers;

import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import org.mapstruct.AfterMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserProfileMapper extends EntityMapper<UserProfileEntity, UserProfileDto> {

    // IGNORE fullName - It's compute it manually
    @Override
    @Mapping(target = "fullName", ignore = true)
    @Mapping(target = "userId", expression = "java(entity.getUser() != null ? entity.getUser().getId() : null)")
    @Mapping(target = "username", expression = "java(entity.getUser() != null ? entity.getUser().getUsername() : null)")
    @Mapping(target = "status", expression = "java(entity.getUser() != null ? entity.getUser().getStatus() : null)")
    @Mapping(target = "userUpdatedAt", expression = "java(entity.getUser() != null ? entity.getUser().getUpdatedAt() : null)")
    @Mapping(target = "session", expression = "java(entity.getUser() != null && entity.getUser().getSession() != null && !entity.getUser().getSession().isEmpty() ? \"Online\" : \"Offline\")")
    UserProfileDto mapTo(UserProfileEntity entity);

    @Override
    @Mapping(target = "user", ignore = true) // service handles linking user
    UserProfileEntity mapFrom(UserProfileDto dto);

    // Custom fullName builder
    @AfterMapping
    default void computeFullName(UserProfileEntity entity, @MappingTarget UserProfileDto dto) {
        String first = entity.getFirstName() != null ? entity.getFirstName() : "";
        String middle = entity.getMiddleName() != null ? entity.getMiddleName() : "";
        String last = entity.getLastName() != null ? entity.getLastName() : "";

        String fullName = String.format("%s %s %s", first, middle, last)
                .replaceAll(" +", " ")
                .trim();

        dto.setFullName(fullName);
    }
}
