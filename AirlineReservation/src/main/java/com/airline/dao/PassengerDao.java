package com.airline.dao;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.airline.entity.Passenger;

@Repository
public interface PassengerDao extends JpaRepository<Passenger, Long> {

}