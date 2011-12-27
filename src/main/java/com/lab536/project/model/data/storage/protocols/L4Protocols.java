package com.lab536.project.model.data.storage.protocols;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public enum L4Protocols implements Protocols{
	ICMP 	(new Icmp(), "ICMP"),
	TCP 	(new Tcp(), "TCP"),
	UDP		(new Udp(), "UDP");
	
	private JHeader header;
	private String presentation;

	private L4Protocols(JHeader header, String s){
		this.header = header;
		this.presentation = s;
	}
	
	public JHeader getHeader(){
		return header;
	}
	
	public static Protocols getProtocol(JPacket p) {
		for(L4Protocols tp : L4Protocols.values()){
			if(p.hasHeader(tp.header)){
				return tp;
			}
		}
		return null;
	}
	
	@Override
	public String toString(){
		return presentation;
	}
	
	public static int getDestPort(JPacket packet, L4Protocols l4header) {
		switch(l4header){
			case TCP:
				return packet.getHeader(new Tcp()).destination();
			case UDP:
				return packet.getHeader(new Udp()).destination();
		}
		return -1;
	}

	public static int getSourcePort(JPacket packet, L4Protocols l4header) {
		switch(l4header){
			case TCP:
				return packet.getHeader(new Tcp()).source();
			case UDP:
				return packet.getHeader(new Udp()).source();
		}
		return -1;
	}
	
	public static int getICMPCode(JPacket packet, L4Protocols l4header) {
		switch(l4header){
			case ICMP:
				return packet.getHeader(new Icmp()).code();
		}
		return -1;
	}
	
}
