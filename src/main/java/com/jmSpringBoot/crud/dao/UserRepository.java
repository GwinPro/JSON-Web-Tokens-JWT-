package com.jmSpringBoot.crud.dao;

import com.jmSpringBoot.crud.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository("UserRepository")
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("FROM User us JOIN FETCH us.roles where us.email = :email")
    User getUserByName(@Param("email") String email);

    @Query("FROM User us JOIN FETCH us.roles")
    List<User> getAll();


}
