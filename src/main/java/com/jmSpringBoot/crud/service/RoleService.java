package com.jmSpringBoot.crud.service;

import com.jmSpringBoot.crud.model.Role;

import java.util.List;


public interface RoleService {
    Role getRoleById(long id);
    Role getRoleByName(String roleName);
    void addRole(Role role);
    void updateRole(Role role);
    void deleteRole(long id);
    List<Role> getRoles();
}