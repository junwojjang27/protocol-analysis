import java.util.Scanner;

public class protocolAnalysis {
	String protocol;
	String EF, IP, TCP, ARP, ICMP, UDP;
	
	public static void main(String[] args) {
//		String protocol = "001e902ec7eb0019e77a753f080045000034dbf74000f206e2ecdc5fe9abde6a25690050c61215e928e73538db8780121ffe6f360000020405b40103030201010402";
		//Ethernet + IP + TCP 테스트
		
//		String protocol = "ffffffffffff001e9035b11408060001080006040001001e9035b114c0a8011a000000000000c0a80101000000000000000000000000000000000000";
		//Ethernet + ARP 테스트
		
//		String protocol = "00d0024f080a0013778e244708004500005c049d00000101efd7cbfc1631cbfc17030800ecff0200090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
		//Ethernet + IP + ICMP 테스트
		
//		String protocol = "001e902ec7eb0019e77a753f080045000034dbf74000f211e2ecdc5fe9abde6a2569" + "1f9056789123456789123456789123456789123456789123456789123456789";
		//Ethernet + IP + UDP 테스트	(Ethernet과 IP에서 type을 제외한 부분은 첫번째 프로토콜과 같음. UDP부분만 임의 설정)
		
		Scanner scan = new Scanner(System.in);		//직접 입력받을 때 사용.
		System.out.print("protocol 입력 : ");
		String protocol = scan.next();
		
		protocolAnalysis A = new protocolAnalysis();		
		
		A.Analysis(protocol);
		
		scan.close();
	}
	
	
	
	void Analysis(String protocol) {
		this.protocol = protocol;
		EF = protocol.substring(0, 28);
		Ethernet(EF);
	}
	
	void Ethernet(String EF) {									//Ethernet
		String EF_d = EF.substring(0, 12);		//Destination Address
		String EF_s = EF.substring(12, 24);		//Source Address
		String EF_t = EF.substring(24, 28);		//Type
		int x=0, y=2;
		
		System.out.println("1. Ethernet");		

		System.out.print("\t1) Destination Address : ");
		for(int i=0; i<6; i++) {			
			System.out.print(EF_d.substring(x,y));
			if(i==5) {
				x=0; y=2;
				if(Integer.parseInt(EF_d.substring(0,2), 16)%2 == 0)		//유니캐스트 멀티캐스트 구분
					if(EF_d.equals("000000000000"))
						System.out.println("\t(Unknown)");
					else
						System.out.println("\t(Unicast)");
				else {
					if(EF_d.equals("ffffffffffff"))
						System.out.println("\t(Broadcast)");						
					else
						System.out.println("\t(Multicast)");
				}					
				break;
			}
			x+=2; y+=2;
			System.out.print(":");
		}
		
		System.out.print("\t2) Source Address : ");
		for(int i=0; i<6; i++) {			
			System.out.print(EF_s.substring(x,y));
			if(i==5) {
				x=0; y=2;
				if(Integer.parseInt(EF_s.substring(0,2))%2 == 0)		//유니캐스트 멀티캐스트 구분
					if(EF_s.equals("000000000000"))
						System.out.println("\t(Unknown)");
					else
						System.out.println("\t(Unicast)");
				else
					if(EF_s.equals("ffffffffffff"))
						System.out.println("\t(Broadcast)");						
					else
						System.out.println("\t(Multicast)");
				break;
			}
			x+=2; y+=2;
			System.out.print(":");
		}		
		
		System.out.print("\t3) Type : " + EF_t);						
		if(EF_t.equals("0800")) {
			System.out.println("\t(IP)");
			IP = protocol.substring(EF.length(), EF.length()+40);			
			IP(IP);
		}
		else if(EF_t.equals("0806")) {
			System.out.println("\t(ARP)");
			ARP = protocol.substring(EF.length(), protocol.length());
			ARP(ARP);
		}
			
	}
	
	void IP(String IP) {				//IP
		String IP_v = IP.substring(0,1);		//version
		String IP_h = IP.substring(1,2);		//header length
		String IP_s = IP.substring(2,4);		//service type
		String IP_t = IP.substring(4,8);		//total length
		String IP_i = IP.substring(8,12);		//identification
		String IP_f = IP.substring(12,13);		//flags
		String IP_o = IP.substring(13,16);		//offset
		String IP_tt = IP.substring(16,18);		//ttl
		String IP_p = IP.substring(18, 20);		//protocol
		String IP_c = IP.substring(20, 24);		//checksum
		String IP_so = IP.substring(24, 32);	//source address
		String IP_d = IP.substring(32, 40);		//destination address
		int x=0, y=2;
		
		System.out.println("2. IP");
		
		System.out.println("\t1) Version : " + IP_v);
		
		System.out.print("\t2) Header Length : " + IP_h);
		System.out.println("\t\t(" + Integer.parseInt(IP_h)*4 + "byte)");
		
		System.out.println("\t3) Service Type : " + IP_s);
		
		System.out.print("\t4) Total Length : " + IP_t);
		System.out.println("\t\t(" + Integer.parseInt(IP_t, 16) + " bytes : " + (Integer.parseInt(IP_t, 16)-Integer.parseInt(IP_h)*4) + " bytes payload)");
		
		System.out.println("\t5) Identification : " + IP_i + "\t(" + Integer.parseInt(IP_i, 16) + ")");
		
		System.out.print("\t6) Flags : " + IP_f);
		String flag = Integer.toBinaryString(Integer.parseInt(IP_f, 16));
		while (true) {
			int num = flag.length();
			if (num == 4)
				break;
			else
				flag = "0" + flag;
		}
		System.out.println("\t\t\t(" + flag + ")");
		System.out.println("\t  - Reserve : " + flag.substring(0,1));
		System.out.print("\t  - Don't Fragment : " + flag.substring(1,2));
		if(flag.substring(1,2).equals("0"))
			System.out.println("\t(Able to fragment)");
		else
			System.out.println("\t(Unable to fragment)");
		System.out.print("\t  - More : " + flag.substring(2,4));
		if(flag.substring(2,4).equals("00"))
			System.out.println("\t\t(No more Fragments)");
		else
			System.out.println("\t\t(More Fragments)");
		
		System.out.println("\t7) Offset : " + IP_o);
		
		System.out.print("\t8) TTL : " + IP_tt);
		System.out.println("\t\t\t(" + Integer.parseInt(IP_tt, 16) + " hops)");
		
		System.out.print("\t9) Protocol : " + IP_p);
		if(IP_p.equals("06")) {
			System.out.println("\t\t(TCP)");
			TCP = protocol.substring(EF.length()+IP.length(), protocol.length());
		}
		else if(IP_p.equals("01")) {
			System.out.println("\t\t(ICMP)");
			ICMP = protocol.substring(EF.length()+IP.length(), protocol.length());
		}
		else if(IP_p.equals("11")) {
			System.out.println("\t\t(UDP)");
			UDP = protocol.substring(EF.length()+IP.length(), protocol.length());
		}
		
		System.out.println("\t10) Checksum : " + IP_c);
		
		System.out.print("\t11) Source Address : " + IP_so + "\t\t(");
		for(int i=0; i<4; i++) {			
			System.out.print(Integer.parseInt(IP_so.substring(x,y), 16));
			if(i==3) {
				x=0; y=2;
				break;
			}			
			x+=2; y+=2;
			System.out.print(".");
		}
		System.out.println(")");
		
		System.out.print("\t12) Destination Address : " + IP_d + "\t(");
		for(int i=0; i<4; i++) {			
			System.out.print(Integer.parseInt(IP_d.substring(x,y), 16));
			if(i==3) {
				x=0; y=2;
				break;
			}			
			x+=2; y+=2;
			System.out.print(".");
		}
		System.out.println(")");
		
		if(IP_p.equals("06"))
			TCP(TCP);
		else if(IP_p.equals("01"))
			ICMP(ICMP);
		else if(IP_p.equals("11"))
			UDP(UDP);
	}
	
	void TCP(String TCP) {					//TCP
		String TCP_s = TCP.substring(0,4);			//Source Port
		String TCP_d = TCP.substring(4,8);			//Destination Port
		String TCP_se = TCP.substring(8,16);		//Sequence number
		String TCP_a = TCP.substring(16,24);		//Ack number
		String TCP_h = TCP.substring(24,25);		//Header Length
		String TCP_c = TCP.substring(26,28);		//Control Bits
		String TCP_w = TCP.substring(28,32);		//Window Size
		String TCP_ch = TCP.substring(32,36);		//Checksum
		String TCP_u = TCP.substring(36,40);		//Urgent Point
		String TCP_o = TCP.substring(40,TCP.length());	//Option
		
		
		System.out.println("3. TCP");
		
		System.out.print("\t1) Source Port : " + TCP_s);
		if (TCP_s.equals("0050"))
			System.out.println("\t\t(" + Integer.parseInt(TCP_s, 16) + " : WWW)");
		if (TCP_s.equals("0015"))
			System.out.println("\t\t(" + Integer.parseInt(TCP_s, 16) + " : FTP -> control)");
		if (TCP_s.equals("0017"))
			System.out.println("\t\t(" + Integer.parseInt(TCP_s, 16) + " : Telnet)");
		if (TCP_s.equals("1f90"))
			System.out.println("\t\t(" + Integer.parseInt(TCP_s, 16) + " : Alternate HTTP)");
		
		
		System.out.print("\t2) Destination Port : " + TCP_d);
		System.out.println("\t(" + Integer.parseInt(TCP_d, 16) + " : Client Port)");
		
		System.out.println("\t3) Sequence number : " + TCP_se);
		
		System.out.println("\t4) Ack number : " + TCP_a);
		
		System.out.print("\t5) Header Length : " + TCP_h);
		int option = (4*Integer.parseInt(TCP_h, 16)-20);
		System.out.println("\t(" + (4*Integer.parseInt(TCP_h, 16)) + " bytes : option " + option + " bytes)");
		
		System.out.print("\t6) Control Bits : " + TCP_c + "\t( ");
		String contrl;
		int n = 0;
		String con = "";
		for(int i=1; i<3; i++) {
			contrl = Integer.toBinaryString(Integer.parseInt(TCP_c.substring(n,i), 16));
			while (true) {
				int num = contrl.length();
				if (num == 4) {
					System.out.print(contrl +" ");
					con = con + contrl;
					contrl = "";
					break;
				}
				else
					contrl = "0" + contrl;
			}
			n++;
		}
		System.out.println(")");
		System.out.println("\t  -Urgent : " + con.substring(2,3));
		System.out.println("\t  -AcK : " + con.substring(3,4));
		System.out.println("\t  -Push : " + con.substring(4,5));
		System.out.println("\t  -Reset : " + con.substring(5,6));
		System.out.println("\t  -Syn : " + con.substring(6,7));
		System.out.println("\t  -Fin : " + con.substring(7,8));
		
		System.out.print("\t7) Window Size : " + TCP_w);
		System.out.println("\t(" + Integer.parseInt(TCP_w, 16) + " bytes)");
		
		System.out.println("\t8) Checksum : " + TCP_ch);
		
		System.out.println("\t9) Urgent Point : " + TCP_u);
		
		System.out.println("\t10) Option : " + TCP_o + "\t(" + option + " bytes)");		
	}

	void ARP(String ARP) {
		String ARP_ht = ARP.substring(0,4);		//H/WType
		String ARP_pt = ARP.substring(4,8);		//Protocol Type
		String ARP_hs = ARP.substring(8,10);	//H/W Size
		String ARP_ps = ARP.substring(10,12);	//Protocol Size
		String ARP_o = ARP.substring(12,16);	//Operation
		String ARP_sm = ARP.substring(16,28);	//Sender MAC Address
		String ARP_si = ARP.substring(28,36);	//Sender IP Address
		String ARP_tm = ARP.substring(36,48);	//Target MAC Address
		String ARP_ti = ARP.substring(48, 56);	//Target IP Address
		int x=0, y=2;
		
		System.out.println("2. ARP");
		
		System.out.print("\t1) H/W Type : " + ARP_ht);
		if(ARP_ht.equals("0001"))
			System.out.println("\t\t(Ethernet)");
		
		System.out.print("\t2) Protocol Type : " + ARP_pt);
		if(ARP_pt.equals("0800"))
			System.out.println("\t\t(IP)");
		
		System.out.print("\t3) H/W Size : " + ARP_hs);
		System.out.println("\t\t(" + Integer.parseInt(ARP_hs, 16)*8 + " bits)");
		
		System.out.print("\t4) Protocol Size : " + ARP_ps);
		System.out.println("\t\t(" + Integer.parseInt(ARP_ps, 16)*8 + " bits)");
		
		System.out.print("\t5) Operation : " + ARP_o);
		System.out.println("\t\t(ARP Request)");
		
		System.out.print("\t6) Sender MAC Address : ");
		for(int i=0; i<6; i++) {			
			System.out.print(ARP_sm.substring(x,y));
			if(i==5) {
				x=0; y=2;
				if(Integer.parseInt(ARP_sm.substring(0,2), 16)%2 == 0)
					if(ARP_sm.equals("000000000000"))
						System.out.println("\t(Unknown)");
					else
						System.out.println("\t(Unicast)");
				else {
					if(ARP_sm.equals("ffffffffffff"))
						System.out.println("\t(Broadcast)");						
					else
						System.out.println("\t(Multicast)");
				}					
				break;
			}
			x+=2; y+=2;
			System.out.print(":");
		}
		
		System.out.print("\t7) Sender IP Address : " + ARP_si + "\t(");
		for(int i=0; i<4; i++) {			
			System.out.print(Integer.parseInt(ARP_si.substring(x,y), 16));
			if(i==3) {
				x=0; y=2;
				break;
			}			
			x+=2; y+=2;
			System.out.print(".");
		}
		System.out.println(")");
		
		System.out.print("\t8) Target Mac Address : ");
		for(int i=0; i<6; i++) {			
			System.out.print(ARP_tm.substring(x,y));
			if(i==5) {
				x=0; y=2;
				if(Integer.parseInt(ARP_tm.substring(0,2), 16)%2 == 0)
					if(ARP_tm.equals("000000000000"))
						System.out.println("\t(Unknown)");
					else
						System.out.println("\t(Unicast)");
				else {
					if(ARP_tm.equals("ffffffffffff"))
						System.out.println("\t(Broadcast)");						
					else
						System.out.println("\t(Multicast)");
				}					
				break;
			}
			x+=2; y+=2;
			System.out.print(":");
		}
		
		System.out.print("\t9) Target IP Address : " + ARP_ti + "\t(");
		for(int i=0; i<4; i++) {			
			System.out.print(Integer.parseInt(ARP_ti.substring(x,y), 16));
			if(i==3) {
				x=0; y=2;
				break;
			}			
			x+=2; y+=2;
			System.out.print(".");
		}
		System.out.println(")");		
	}
	
	void ICMP(String ICMP) {
		String ICMP_t = ICMP.substring(0,2);	//Type
		String ICMP_co = ICMP.substring(2,4);	//Code
		String ICMP_ch = ICMP.substring(4,8);	//Checksum
		String ICMP_i = ICMP.substring(8,12);	//Identifier
		String ICMP_s = ICMP.substring(12,16);	//Sequence number
		
		System.out.println("3. ICMP");
		
		System.out.print("\t1) Type : " + ICMP_t);
		if(ICMP_t.equals("00"))
			System.out.println("\t (Echo Reply)");
		else if(ICMP_t.equals("03"))
			System.out.println("\t (Destination Unreachable)");
		else if(ICMP_t.equals("05"))
			System.out.println("\t (Redirect)");
		else if(ICMP_t.equals("08"))
			System.out.println("\t (Echo Request)");
		else if(ICMP_t.equals("11"))
			System.out.println("\t (Time Exceeded)");
		
		System.out.print("\t2) Code : " + ICMP_co);
		if(ICMP_t.equals("03"))
			if(ICMP_co.equals("00"))
				System.out.println("\t (Network Unreachable)");
			else if(ICMP_co.equals("01"))
				System.out.println("\t (Host Unreachable)");
			else if(ICMP_co.equals("02"))
				System.out.println("\t (Protocol Unreachalbe)");
			else if(ICMP_co.equals("06"))
				System.out.println("\t (Destination Network Unknown)");
			else if(ICMP_co.equals("07"))
				System.out.println("\t (Destination Host Unknown)");
		if(ICMP_t.equals("05"))
			if(ICMP_co.equals("00"))
				System.out.println("\t (Redirect Datagram for the Network)");
			else if(ICMP_co.equals("01"))
				System.out.println("\t (Redirect Datagram for the host)");
		if(ICMP_t.equals("11"))
			if(ICMP_co.equals("00"))
				System.out.println("\t (Time to Live exceeded in Transit)");
			else if(ICMP_co.equals("01"))
				System.out.println("\t (Fragment Reassembly Time Exceeded)");
			else
				System.out.println();
		else
			System.out.println();
			
		
		System.out.println("\t3) Checksum : " + ICMP_ch);
		
		System.out.println("\t4) Identifier : " + ICMP_i);
		
		System.out.println("\t5) Sequence number : " + ICMP_s);
		
//		System.out.println("\n\tQuery messages : " + ICMP.substring(16,ICMP.length()));
	}
	
	void UDP(String UDP) {
		String UDP_s = UDP.substring(0,4);		//Source port number
		String UDP_d = UDP.substring(4,8);		//Destination port number
		String UDP_t = UDP.substring(8,12);		//Total length
		String UDP_c = UDP.substring(12,16);	//Checksum
		
		
		System.out.println("3. UDP");
		
		System.out.print("\t1) Source port : " + UDP_s);
		if (UDP_s.equals("1f90"))
			System.out.println("\t\t(" + Integer.parseInt(UDP_s, 16) + " : DNS)");	//UDP port
		
		System.out.print("\t2) Destination port : " + UDP_d);
		System.out.println("\t(" + Integer.parseInt(UDP_d, 16) + " : Client Port)");
		
		System.out.println("\t3) Header length : " + UDP_t);
		
		System.out.println("\t4) Checksum : " + UDP_c);
		
//		System.out.println("\n\tData : " + UDP.substring(16,UDP.length()));
	}	
}
