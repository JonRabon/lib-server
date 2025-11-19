package com.coderepojon.dbPostgres.repositories;

import com.coderepojon.dbPostgres.TestDataUtil;
import com.coderepojon.dbPostgres.domain.entities.AuthorEntity;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
@ExtendWith(SpringExtension.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class AuthorEntityRepositoryIntegrationTests {

    private final AuthorRepository underTest;

    @Autowired
    private BookRepository bookRepository;

    @Autowired
    public AuthorEntityRepositoryIntegrationTests(AuthorRepository underTest) {
        this.underTest = underTest;
    }

    @BeforeEach
    void setUp() {
        bookRepository.deleteAll(); // delete dependent books first
        underTest.deleteAll();      // now safe to delete authors
    }

    @Test
    public void testThatAuthorCanBeCreatedAndRecalled() {
        AuthorEntity author = TestDataUtil.createTestAuthorEntityA();
        underTest.save(author);

        AuthorEntity result = underTest.findById(author.getId()).orElse(null);
        assertThat(result).isNotNull();
        assertThat(result).isEqualTo(author);
    }

    @Test
    public void testThatMultipleAuthorsCanBeCreatedAndRecalled() {
        AuthorEntity authorA = TestDataUtil.createTestAuthorEntityA();
        AuthorEntity authorB = TestDataUtil.createTestAuthorB();
        AuthorEntity authorC = TestDataUtil.createTestAuthorC();

        underTest.save(authorA);
        underTest.save(authorB);
        underTest.save(authorC);

        List<AuthorEntity> result = (List<AuthorEntity>) underTest.findAll();
        assertThat(result)
                .hasSize(3)
                .containsExactlyInAnyOrder(authorA, authorB, authorC);
    }

    @Test
    public void testThatAuthorCanBeUpdated() {
        AuthorEntity author = TestDataUtil.createTestAuthorEntityA();
        underTest.save(author);

        author.setName("UPDATED");
        underTest.save(author);

        AuthorEntity result = underTest.findById(author.getId()).orElse(null);
        assertThat(result).isNotNull();
        assertThat(result.getName()).isEqualTo("UPDATED");
    }

    @Test
    public void testThatAuthorCanBeDeleted() {
        AuthorEntity author = TestDataUtil.createTestAuthorEntityA();
        underTest.save(author);

        underTest.deleteById(author.getId());

        assertThat(underTest.findById(author.getId())).isEmpty();
    }

    @Test
    public void testThatAuthorsWithAgeLessThan() {
        AuthorEntity authorA = TestDataUtil.createTestAuthorEntityA();
        AuthorEntity authorB = TestDataUtil.createTestAuthorB();
        AuthorEntity authorC = TestDataUtil.createTestAuthorC();

        underTest.save(authorA);
        underTest.save(authorB);
        underTest.save(authorC);

        List<AuthorEntity> result = underTest.findByAgeLessThan(50);

        assertThat(result)
                .hasSize(2)
                .containsExactlyInAnyOrder(authorB, authorC);
    }

    @Test
    public void testThatGetAuthorsWithAgeGreaterThan() {
        AuthorEntity authorA = TestDataUtil.createTestAuthorEntityA();
        AuthorEntity authorB = TestDataUtil.createTestAuthorB();
        AuthorEntity authorC = TestDataUtil.createTestAuthorC();

        underTest.save(authorA);
        underTest.save(authorB);
        underTest.save(authorC);

        List<AuthorEntity> result = underTest.findAuthorWithAgeGreaterThan(50);

        assertThat(result)
                .hasSize(1)
                .containsExactly(authorA);
    }
}
