package com.kp.webapp.security.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
      /*  UserInfo user = userRepo.findByUsername(username);
        if (user == null) {
                throw new UsernameNotFoundException("user not found");
        }
        
        return new UserPrincipal(user);
    */
        Optional<UserInfo> userInfo = userRepo.findByUsername(username);
        return userInfo.map(UserPrincipal::new).orElseThrow(
                () -> new UsernameNotFoundException("User not Found" + username));
    }
}