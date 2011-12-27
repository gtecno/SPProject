package com.lab536.project.model.data.storage.protocols;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;

import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;


public enum L3Protocols implements Protocols{
	IPv4	(new Ip4()),
	IPv6	(new Ip6());
	
	private JHeader header;

	private L3Protocols(JHeader header){
		this.header = header;
	}
	
	public JHeader getHeader(){
		return header;
	}
	
	public static Protocols getProtocol(JPacket p) {
		for(L3Protocols np : L3Protocols.values()){
			if(p.hasHeader(np.header)){
				return np;
			}
		}
		return null;
	}

	public static byte[] getDestIP(JPacket packet, L3Protocols l3header) {
		switch(l3header){
			case IPv4:
				return packet.getHeader(new Ip4()).destination();
			case IPv6:
				return packet.getHeader(new Ip6()).destination();
		}
		return null;
	}

	public static byte[] getSourceIP(JPacket packet, L3Protocols l3header) {
		switch(l3header){
			case IPv4:
				return packet.getHeader(new Ip4()).source();
			case IPv6:
				return packet.getHeader(new Ip6()).source();
		}
		return null;
	}
}
