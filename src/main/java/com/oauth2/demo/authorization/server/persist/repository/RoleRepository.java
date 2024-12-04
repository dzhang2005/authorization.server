package com.oauth2.demo.authorization.server.persist.repository;

import com.oauth2.demo.authorization.server.persist.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
