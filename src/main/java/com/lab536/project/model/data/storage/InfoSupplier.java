package com.lab536.project.model.data.storage;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;



public class InfoSupplier {
	
	public static List<PcapIf> getInterfaces(Pcap pcap){
		 List<PcapIf> ifs = new ArrayList<PcapIf>(); // Will hold list of devices
		 int statusCode = Pcap.findAllDevs(ifs, new StringBuilder());
		 if (statusCode != Pcap.OK) {
			 throw new IllegalArgumentException(pcap.getErr());
		 }
		 return ifs;
	}
	
	public static PcapBpfProgram getFilter(Pcap pcap, String filter, int optimize, int netmask){
		PcapBpfProgram program = new PcapBpfProgram();
		int i = pcap.compile(program, filter, optimize, netmask);
		if(i != Pcap.OK){
			throw new IllegalArgumentException(pcap.getErr());
		}
		return program;
	}
	
}
