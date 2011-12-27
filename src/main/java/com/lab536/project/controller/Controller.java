package com.lab536.project.controller;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;

import com.lab536.project.model.data.storage.Storage;

public class Controller {
	private Capturer capturer;
	private final Storage storage = new Storage();
	
	public Controller(PcapIf deviceInt, int snaplen, int flags, int timeout){
		initializeCapturer(deviceInt, snaplen, flags, timeout);
	}
	
	private void initializeCapturer(PcapIf deviceInt, int snaplen, int flags, int timeout){
		capturer = new Capturer(deviceInt, snaplen, flags, timeout);
		capturer.setListener(new JPacketHandler<String>() {
			
			@Override
			public void nextPacket(JPacket packet, String user) {
				storage.addPacket(packet);
			}
		});
	}
	
	public void startCapture(){
		capturer.start();
	}
	
	public void stopCapture(){
		capturer.stopCapture();
	}
	
	public void setFilter(String filter){
		capturer.setFilter(filter);
	}
}
