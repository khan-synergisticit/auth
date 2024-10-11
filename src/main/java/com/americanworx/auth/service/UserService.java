package com.americanworx.auth.service;

import com.americanworx.auth.domain.UserDtls;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserService {
    public UserDtls saveUser(UserDtls user);

    public UserDtls getUserByEmail(String email);

    public List<UserDtls> getUsers(String role);


    public Boolean existsEmail(String email);
}
