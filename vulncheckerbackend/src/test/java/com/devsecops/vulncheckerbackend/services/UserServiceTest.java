package com.devsecops.vulncheckerbackend.services;

import com.devsecops.vulncheckerbackend.entities.UserEntity;
import com.devsecops.vulncheckerbackend.repositories.UserRepository;
import com.devsecops.vulncheckerbackend.support.TestDataFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @InjectMocks
    private UserService userService;

    @Test
    void login_returnsUser_whenEmailExistsAndPasswordMatchesAndUserActive() {
        UserEntity user = TestDataFactory.user(1L);
        user.setPassword("encoded");
        user.setActive(true); // <-- CRUCIAL

        when(userRepository.findByEmail("admin.seguridad@usach.cl")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("admin123", "encoded")).thenReturn(true);

        Optional<UserEntity> result = userService.login("admin.seguridad@usach.cl", "admin123");

        assertTrue(result.isPresent());
        assertEquals("admin.seguridad@usach.cl", result.get().getEmail());
    }

    @Test
    void login_returnsEmpty_whenPasswordDoesNotMatch() {
        UserEntity user = TestDataFactory.user(1L);
        user.setPassword("encoded");
        user.setActive(true); // <-- CRUCIAL

        when(userRepository.findByEmail("admin.seguridad@usach.cl")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("bad-password", "encoded")).thenReturn(false);

        Optional<UserEntity> result = userService.login("admin.seguridad@usach.cl", "bad-password");

        assertTrue(result.isEmpty());
    }

    @Test
    void login_returnsEmpty_whenUserDoesNotExist() {
        when(userRepository.findByEmail("missing@usach.cl")).thenReturn(Optional.empty());

        Optional<UserEntity> result = userService.login("missing@usach.cl", "admin123");

        assertTrue(result.isEmpty());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void login_returnsEmpty_whenUserExistsButIsInactive() {
        UserEntity user = TestDataFactory.user(1L);
        user.setPassword("encoded");
        user.setActive(false); // inactivo

        when(userRepository.findByEmail("admin.seguridad@usach.cl")).thenReturn(Optional.of(user));
        // No debería llamarse a passwordEncoder porque el filtro de active falla primero
        Optional<UserEntity> result = userService.login("admin.seguridad@usach.cl", "admin123");

        assertTrue(result.isEmpty());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void save_encodesPasswordBeforePersisting() {
        UserEntity user = TestDataFactory.user(1L);
        user.setPassword("admin123");

        when(passwordEncoder.encode("admin123")).thenReturn("encoded-pass");
        when(userRepository.save(any(UserEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserEntity saved = userService.save(user);

        assertEquals("encoded-pass", saved.getPassword());
        verify(userRepository).save(user);
    }

    @Test
    void findByActiveFalse_returnsInactiveUsers() {
        List<UserEntity> inactive = List.of(TestDataFactory.user(2L));
        when(userRepository.findByActiveFalse()).thenReturn(inactive);

        List<UserEntity> result = userService.findByActiveFalse();

        assertEquals(1, result.size());
        verify(userRepository).findByActiveFalse();
    }

    @Test
    void findByEmail_returnsUserWhenFound() {
        UserEntity user = TestDataFactory.user(1L);
        when(userRepository.findByEmail("admin.seguridad@usach.cl")).thenReturn(Optional.of(user));

        Optional<UserEntity> result = userService.findByEmail("admin.seguridad@usach.cl");

        assertTrue(result.isPresent());
        assertEquals("admin.seguridad@usach.cl", result.get().getEmail());
    }

    @Test
    void findByEmail_returnsEmptyWhenNotFound() {
        when(userRepository.findByEmail("unknown@test.cl")).thenReturn(Optional.empty());

        Optional<UserEntity> result = userService.findByEmail("unknown@test.cl");

        assertTrue(result.isEmpty());
    }

    @Test
    void findAll_returnsAllUsers() {
        List<UserEntity> users = List.of(TestDataFactory.user(1L), TestDataFactory.user(2L));
        when(userRepository.findAll()).thenReturn(users);

        List<UserEntity> result = userService.findAll();

        assertEquals(2, result.size());
        verify(userRepository).findAll();
    }

    @Test
    void findById_returnsUserWhenFound() {
        UserEntity user = TestDataFactory.user(1L);
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        Optional<UserEntity> result = userService.findById(1L);

        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
    }

    @Test
    void findById_returnsEmptyWhenNotFound() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        Optional<UserEntity> result = userService.findById(99L);

        assertTrue(result.isEmpty());
    }

    @Test
    void deleteById_delegatesToRepository() {
        userService.deleteById(1L);

        verify(userRepository).deleteById(1L);
    }

    @Test
    void saveDirectly_persistsWithoutEncoding() {
        UserEntity user = TestDataFactory.user(1L);
        userService.saveDirectly(user);

        verify(userRepository).save(user);
        verify(passwordEncoder, never()).encode(any());
    }
}