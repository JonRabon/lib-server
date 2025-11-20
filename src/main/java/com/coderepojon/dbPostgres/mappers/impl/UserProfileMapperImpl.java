package com.coderepojon.dbPostgres.mappers.impl;

import com.coderepojon.dbPostgres.domain.dto.UserProfileDto;
import com.coderepojon.dbPostgres.domain.entities.UserProfileEntity;
import com.coderepojon.dbPostgres.mappers.Mapper;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.springframework.stereotype.Component;

@Component
public class UserProfileMapperImpl implements Mapper<UserProfileEntity, UserProfileDto> {

    private final ModelMapper modelMapper;

    public UserProfileMapperImpl(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;

        // IGNORE fullName during mapping
        this.modelMapper.addMappings(new PropertyMap<UserProfileEntity, UserProfileDto>() {
            @Override
            protected void configure() {
                skip(destination.getFullName()); // <-- correct way
            }
        });
    }

    @Override
    public UserProfileDto mapTo(UserProfileEntity entity) {
        UserProfileDto dto = modelMapper.map(entity, UserProfileDto.class);

        if (entity.getUser() != null) {
            dto.setUserId(entity.getUser().getId());
        }

        //Manually compute fullname
        dto.setFullName(buildFullName(entity));
        return dto;
    }

    @Override
    public UserProfileEntity mapFrom(UserProfileDto dto) {
        UserProfileEntity entity = modelMapper.map(dto, UserProfileEntity.class);
        // Do not set userId here - it is handled is service when creating
        return entity;
    }

    private String buildFullName(UserProfileEntity e) {
        return String.join(" ",
                e.getFirstName() != null ? e.getFirstName() : "",
                e.getMiddleName() != null ? e.getMiddleName() : "",
                e.getLastName() != null ? e.getLastName() : ""
        ).trim().replaceAll(" +", " ");
    }
}
