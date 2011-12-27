package com.lab536.project.model.data.storage;

import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.format.FormatUtils;

import com.lab536.project.model.data.storage.protocols.L2Protocols;
import com.lab536.project.model.data.storage.protocols.L3Protocols;
import com.lab536.project.model.data.storage.protocols.L4Protocols;

public class Packet{
	private int id;
	private JPacket packet;
	public final L2Protocols l2header;
	public final L3Protocols l3header;
	public final L4Protocols l4header;
	
	public Packet(JPacket packet, int i){
		if(packet == null){
			throw new IllegalArgumentException("Empty packet");
		}
		this.id = i;
		this.packet = packet;
		l2header = (L2Protocols) L2Protocols.getProtocol(packet);
		l3header = (L3Protocols) L3Protocols.getProtocol(packet);
		l4header = (L4Protocols) L4Protocols.getProtocol(packet);
	}
	
	@Override
	public String toString(){
		return packet.toString();
	}
	
	public JHeader getL2Header(){
		return l2header == null ? null : packet.getHeader(l2header.getHeader());
	}
	
	public JHeader getL3Header(){
		return l3header == null ? null : packet.getHeader(l3header.getHeader());
	}
	
	public JHeader getL4Header(){
		return l4header == null ? null : packet.getHeader(l4header.getHeader());
	}
	
	
	/**
	 * First goes Destination address, then source, then highest-level protocol name
	 * @return
	 */
	public String shortRepresentation(){
		String s = ""+id;
		if(l3header != null){
			s += "\t" + FormatUtils.ip(L3Protocols.getDestIP(packet, l3header));
			s += "\t" + FormatUtils.ip(L3Protocols.getSourceIP(packet, l3header));
		}
		else if((l2header != null) && (l2header != L2Protocols.L2TP)){
			s += "\t" + FormatUtils.mac(L2Protocols.getDestMAC(packet, l2header));
			s += "\t" + FormatUtils.mac(L2Protocols.getSourceMAC(packet, l2header));	
		}
		if(l4header != null) {
			s += "\t" + l4header;
			if(l4header == L4Protocols.ICMP){
				s += "\t" + L4Protocols.getICMPCode(packet, l4header);
			} else {
				s += "\t" + L4Protocols.getSourcePort(packet, l4header);
				s += "\t" + L4Protocols.getDestPort(packet, l4header);
			}
		} else if(l2header == L2Protocols.ARP){
			s += "\t" + "ARP";
		}
		return s;
	}
}
