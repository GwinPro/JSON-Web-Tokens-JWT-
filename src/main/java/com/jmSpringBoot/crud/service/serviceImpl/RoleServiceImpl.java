package com.jmSpringBoot.crud.service.serviceImpl;

import com.jmSpringBoot.crud.dao.RoleRepository;
import com.jmSpringBoot.crud.model.Role;
import com.jmSpringBoot.crud.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class RoleServiceImpl  implements RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Transactional
    @Override
    public Role getRoleById(long id) {
        return roleRepository.findById(id).get();
    }

    @Transactional
    @Override
    public Role getRoleByName(String roleName) {
        return roleRepository.getRoleByName(roleName);
    }

    @Transactional
    @Override
    public void addRole(Role role) {
        roleRepository.saveAndFlush(role);
    }

    @Transactional
    @Override
    public void updateRole(Role role) {
        roleRepository.saveAndFlush(role);
    }

    @Transactional
    @Override
    public void deleteRole(long id) {
        roleRepository.deleteById(id);
    }

    @Transactional
    @Override
    public List<Role> getRoles() {
        return roleRepository.findAll();
    }
}
