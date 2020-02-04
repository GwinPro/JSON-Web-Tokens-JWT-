package com.jmSpringBoot.crud.service;

import com.jmSpringBoot.crud.model.User;

import java.util.List;

public interface UserService {
    List<User> getAll();
    User addUser(User user);
    void delete(Long id);
    void updateUser(User user);
    User getUserById(Long id);
    User getUserByName(String userName);
}

