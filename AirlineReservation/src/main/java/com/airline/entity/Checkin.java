package com.airline.entity;



import org.springframework.data.annotation.Id;

import jakarta.persistence.GeneratedValue;

public class Checkin {
	
	@Id
	@GeneratedValue
	private long checkinId;
	
	private String seatNumber;
	
	private String gateNumber;

	public long getCheckinId() {
		return checkinId;
	}

	public void setCheckinId(long checkinId) {
		this.checkinId = checkinId;
	}

	public String getSeatNumber() {
		return seatNumber;
	}

	public void setSeatNumber(String seatNumber) {
		this.seatNumber = seatNumber;
	}

	public String getGateNumber() {
		return gateNumber;
	}

	public void setGateNumber(String gateNumber) {
		this.gateNumber = gateNumber;
	}
	
	public Checkin() {
		
	}

	public Checkin(String seatNumber, String gateNumber) {
		super();
		this.seatNumber = seatNumber;
		this.gateNumber = gateNumber;
	}

	@Override
	public String toString() {
		return "Checkin [checkinId=" + checkinId + ", seatNumber=" + seatNumber + ", gateNumber=" + gateNumber + "]";
	}

}
