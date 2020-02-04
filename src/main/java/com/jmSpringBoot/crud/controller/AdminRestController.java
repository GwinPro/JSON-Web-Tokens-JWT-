package com.jmSpringBoot.crud.controller;

import com.jmSpringBoot.crud.model.Role;
import com.jmSpringBoot.crud.model.User;
import com.jmSpringBoot.crud.service.RoleService;
import com.jmSpringBoot.crud.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CachePut;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/rest/admin/")
public class AdminRestController {
    private final UserService userService;
    private final RoleService roleService;

    @Autowired
    public AdminRestController(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @GetMapping("users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok().body(this.userService.getAll());
    }

    @PostMapping("addUser")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User userFromBase = userService.getUserByName(user.getLogin());
        if (userFromBase != null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().body(userService.addUser(user));
    }

    @GetMapping("roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        return  ResponseEntity.ok().body(this.roleService.getRoles());
    }

    @GetMapping("roles/{id}")
    public ResponseEntity<Role> getRoleById(@PathVariable(value = "id") Long roleId) {
        Role role = roleService.getRoleById(roleId);
        if (role == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().body(role);
    }

    @GetMapping("updateUser/{id}")
    public ResponseEntity<User> getUserById(@PathVariable(value = "id") Long id) {
        User user = userService.getUserById(id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok().body(user);
    }

    @PutMapping("updateUser/{id}")
    public ResponseEntity<User> updateEmployee(@PathVariable(value = "id") Long userId, @Valid @RequestBody User editUser) {
        User user = userService.getUserById(userId);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        user.setEmail(editUser.getEmail());
        user.setLogin(editUser.getLogin());
        user.setPassword(editUser.getPassword());
        user.setRoles(editUser.getRoles());
        userService.updateUser(user);
        return ResponseEntity.ok().body(user);
    }

    @GetMapping(value = "{id}")
    public ResponseEntity<User> viewAdmin (@PathVariable(name = "id") Long id){
        User user = userService.getUserById(id);

        if(user == null){
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}
