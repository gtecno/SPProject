package com.lab536.project.model.data.storage;

import java.util.LinkedList;
import java.util.Observable;
import java.util.Observer;

import org.jnetpcap.packet.JPacket;

public class Storage extends Observable{
	private LinkedList<Packet> packets = new LinkedList<Packet>();
	private Observer o;
	
	public int getLength(){
		return packets.size();
	}
	
	public void addPacket(JPacket packet){
		packets.add(new Packet(packet, packets.size()));
		notifyObserver();
	}
	
	public String shortPresentation(int i){
		return packets.get(i).shortRepresentation();
	}
	
	public Packet getPacket(int i){
		return packets.get(i);
	}

	@Override
	public void addObserver(Observer o){
		this.o = o;
	}
	
	public void notifyObserver(){
		o.update(this, packets.get(packets.size()));
	}
}
