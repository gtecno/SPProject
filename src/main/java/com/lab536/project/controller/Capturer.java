package com.lab536.project.controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacketHandler;

import com.lab536.project.model.data.storage.InfoSupplier;

public class Capturer extends Thread {
	private boolean stop = false;
	private PcapIf deviceInt;
	private int snaplen;
	private int flags;
	private int timeout;
	private String filter;
	private JPacketHandler<String> listener;
	
	public Capturer(PcapIf deviceInt, int snaplen, int flags, int timeout) {
		if(deviceInt == null){
			throw new IllegalArgumentException("Can't capture on no interface");
		}
		this.deviceInt = deviceInt;
		this.snaplen = snaplen;
		this.flags = flags;
		this.timeout = timeout;
	}
	
	public void setFilter(String filter){
		if(filter == null){
			this.filter = "";
		}
		this.filter = filter;
	}
	
	public void stopCapture(){
		stop = true;
	}
	
	public void startCapture(){
		this.start();
	}
	
	public void setListener(JPacketHandler<String> listener){
		this.listener = listener;
	}
	
	public void run(){
		Pcap pcap = Pcap.openLive(deviceInt.getName(), snaplen, flags, timeout, new StringBuilder());
		int optimize = 0;
		int netmask = 0;
		InfoSupplier.getFilter(pcap, filter, optimize, netmask);
		while(!stop){
			pcap.loop(1, listener,"");
		}
		pcap.close();
	}
	
}
