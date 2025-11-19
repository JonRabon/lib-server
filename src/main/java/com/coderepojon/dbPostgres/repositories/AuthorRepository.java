package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.domain.entities.AuthorEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AuthorRepository extends CrudRepository<AuthorEntity, Long> {

    // Derived query method — Spring Data JPA generates the query automatically
    List<AuthorEntity> findByAgeLessThan(int age);

    // Explicit @Query for greater-than query
    @Query("SELECT a FROM AuthorEntity a WHERE a.age > :age")
    List<AuthorEntity> findAuthorWithAgeGreaterThan(@Param("age") int age);
}
