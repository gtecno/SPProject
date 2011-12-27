package com.lab536.project.model.data.storage.protocols;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;

public enum L2Protocols implements Protocols{
	L2TP	(new org.jnetpcap.protocol.vpn.L2TP()),
	ARP		(new Arp()),
	ETH		(new Ethernet());
	
	private JHeader header;

	private L2Protocols(JHeader header){
		this.header = header;
	}
	
	public JHeader getHeader(){
		return header;
	}

	public static Protocols getProtocol(JPacket p) {
		for(L2Protocols dlp : L2Protocols.values()){
			if(p.hasHeader(dlp.header)){
				return dlp;
			}
		}
		return null;
	}

	public static byte[] getDestMAC(JPacket packet, L2Protocols l2header) {
		switch(l2header){
			case ETH:
				return packet.getHeader(new Ethernet()).destination();
			case ARP:
				return packet.getHeader(new Arp()).tha();
		}
		return null;
	}

	public static byte[] getSourceMAC(JPacket packet, L2Protocols l2header) {
		switch(l2header){
			case ETH:
				return packet.getHeader(new Ethernet()).source();
			case ARP:
				return packet.getHeader(new Arp()).sha();
		}
		return null;
	}
}
