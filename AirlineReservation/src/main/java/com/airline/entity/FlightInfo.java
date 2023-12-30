package com.airline.entity;



import org.springframework.data.annotation.Id;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "flightInfo")
public class FlightInfo {
	
	@Id
	@GeneratedValue
	private long flightInfoid;
	
	private String flightNumber;
	
	private String flightType;
	
	private int numberofSeats;
	
	@ManyToOne
	@JoinTable(name = "flightsInfo", joinColumns = {
			@JoinColumn(name = "flightInfoid", referencedColumnName = "flightInfoid") }, inverseJoinColumns = {
					@JoinColumn(name = "airlineId", referencedColumnName = "airlineId") })
	private AirlineInfo airlineInfo;
	
	public FlightInfo() {
		
	}


	public FlightInfo(String flightNumber, String flightType, int numberofSeats, AirlineInfo airlineInfo) {
		super();
		this.flightNumber = flightNumber;
		this.flightType = flightType;
		this.numberofSeats = numberofSeats;
		this.airlineInfo = airlineInfo;
	}



	public String getFlightNumber() {
		return flightNumber;
	}

	public void setFlightNumber(String flightNumber) {
		this.flightNumber = flightNumber;
	}

	public String getFlightType() {
		return flightType;
	}

	public void setFlightType(String flightType) {
		this.flightType = flightType;
	}

	public int getNumberofSeats() {
		return numberofSeats;
	}

	public void setNumberofSeats(int numberofSeats) {
		this.numberofSeats = numberofSeats;
	}

	public AirlineInfo getAirlineInfo() {
		return airlineInfo;
	}
	
	public void setAirlineInfo(AirlineInfo airlineInfo) {
		this.airlineInfo = airlineInfo;
	}

	@Override
	public String toString() {
		return "FlightInfo [flightInfoid=" + flightInfoid + ", flightNumber=" + flightNumber + ", flightType="
				+ flightType + ", numberofSeats=" + numberofSeats + ", airlineInfo=" + airlineInfo + "]";
	}

}