package com.airline.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.airline.dao.UserDao;
import com.airline.entity.User;


@Service
public class UserService {	
	
	@Autowired
	UserDao userDao;
	
	public void registerForm(User user) {
		userDao.save(user);
	}
	
	
	public User findByUserName(String userName){
		return userDao.findByUserName(userName);
	}

}
