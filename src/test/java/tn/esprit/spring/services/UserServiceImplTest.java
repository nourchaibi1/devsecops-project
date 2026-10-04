package tn.esprit.spring.services;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import tn.esprit.spring.entities.User;
import tn.esprit.spring.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    UserRepository userRepository;

    @InjectMocks
    UserServiceImpl userService;

    // ---------- retrieveAllUsers ----------
    @Test
    void retrieveAllUsers_returnsList() {
        List<User> users = Arrays.asList(new User(), new User());
        when(userRepository.findAll()).thenReturn(users);

        List<User> result = userService.retrieveAllUsers();

        assertEquals(2, result.size());
        verify(userRepository).findAll();
    }

    // ---------- addUser ----------
    @Test
    void addUser_returnsSavedUser() {
        User u = new User();
        when(userRepository.save(u)).thenReturn(u);

        assertSame(u, userService.addUser(u));
        verify(userRepository).save(u);
    }

    @Test
    void addUser_returnsNullOnDatabaseError() {
        User u = new User();
        when(userRepository.save(any(User.class))).thenThrow(new RuntimeException("DB down"));

        assertNull(userService.addUser(u));
    }

    // ---------- updateUser ----------
    @Test
    void updateUser_returnsUpdatedUser() {
        User u = new User();
        when(userRepository.save(u)).thenReturn(u);

        assertSame(u, userService.updateUser(u));
    }

    @Test
    void updateUser_returnsNullOnDatabaseError() {
        when(userRepository.save(any(User.class))).thenThrow(new RuntimeException("DB down"));

        assertNull(userService.updateUser(new User()));
    }

    // ---------- deleteUser ----------
    @Test
    void deleteUser_callsRepositoryWithParsedId() {
        userService.deleteUser("5");

        verify(userRepository).deleteById(5L);
    }

    @Test
    void deleteUser_invalidId_doesNotCallRepository() {
        assertDoesNotThrow(() -> userService.deleteUser("abc"));

        verify(userRepository, never()).deleteById(any());
    }

    @Test
    void deleteUser_databaseError_isHandled() {
        doThrow(new RuntimeException("DB down")).when(userRepository).deleteById(3L);

        assertDoesNotThrow(() -> userService.deleteUser("3"));
    }

    // ---------- retrieveUser ----------
    @Test
    void retrieveUser_found() {
        User u = new User();
        when(userRepository.findById(1L)).thenReturn(Optional.of(u));

        assertSame(u, userService.retrieveUser("1"));
    }

    @Test
    void retrieveUser_notFound_returnsNull() {
        when(userRepository.findById(99L)).thenReturn(Optional.empty());

        assertNull(userService.retrieveUser("99"));
    }

    @Test
    void retrieveUser_invalidId_returnsNull() {
        assertNull(userService.retrieveUser("abc"));

        verify(userRepository, never()).findById(any());
    }
}
