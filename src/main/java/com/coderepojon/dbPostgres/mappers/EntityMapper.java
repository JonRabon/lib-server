package com.coderepojon.dbPostgres.mappers;

public interface EntityMapper<A,B>{

    B mapTo(A a);
    A mapFrom(B b);

}
