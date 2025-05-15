1. ![[Pasted image 20250513180811.png]]
	1. 帧 90 到 94：TLS 应用数据交互
		帧 90：
		140.207.55.20 → 192.168.6.197 TLSv1.2 425 Application Data
		服务器（140.207.55.20）向客户端（192.168.6.197）发送加密的 TLS 应用数据。
		可能是微信服务器返回的登录页面或初始化数据。
		帧 91：
		192.168.6.197 → 140.207.55.20 TCP 54 52463 → 443 [ACK]
		客户端回复 ACK，确认收到数据。
		帧 92-94：
		客户端和服务器之间继续进行 TCP 确认和 TLS 应用数据交互（如 ACK、PSH, ACK）。
		可能是客户端处理服务器返回的数据，准备渲染登录页面。
	2. 帧 95 到 100：新的 TCP 连接建立（可能是登录请求）
		帧 95：
		52504 → 80 [SYN]
		客户端（2408:8406:1980:27b:e9d9:48ef:7140:ddb2）向服务器（2408:80f1:21:3003::1f）的 80 端口发送 SYN 包，请求建立新的 TCP 连接。
		可能是客户端准备发送登录请求。
		帧 96-98：
		客户端和服务器完成 TCP 三次握手（SYN, ACK、ACK），连接建立成功。
		帧 99：
		HTTP POST /mmtls/00003033 HTTP/1.1
		客户端通过新建立的连接发送 HTTP POST 请求，路径为 /mmtls/00003033。
		可能是登录请求，包含用户名、密码或其他认证信息。
		帧 100：
		80 → 52504 [ACK]
		服务器回复 ACK，确认收到请求。
	3. 帧 101 到 102：服务器响应登录请求
		帧 101：
		80 → 52504 [ACK] Seq=1 Ack=976 Win=64256 Len=1340
		服务器继续回复 ACK，并可能开始传输响应数据（分片传输，长度为 1340 字节）。
		帧 102：
		HTTP/1.1 200 OK
		服务器返回 200 OK，表示登录请求成功。
		响应中可能包含登录成功的标记、用户会话信息或其他后续操作所需的令牌。
	4. 帧 103 到 104：客户端确认响应
		帧 103：
		52504 → 80 [ACK] Seq=976 Ack=1445 Win=65536 Len=0
		客户端回复 ACK，确认收到服务器的响应。
		帧 104：
		52503 → 8080 [ACK] Seq=469 Ack=637 Win=65024 Len=1340
		客户端与其他服务器（2408:873d:a00:3002::11 的 8080 端口）进行 TCP 数据交互（可能是另一个连接的数据确认）。
		可能是微信客户端在处理登录成功后的其他操作（如加载主页、同步数据等）。
	5. 帧 105 到 119：登录成功后的数据交互
		![[Pasted image 20250513181158.png]]

3. 
	1. C:\Windows\System32>tshark -D                                                                                           1. \Device\NPF_{6EDC9497-FCAB-46A3-9795-B272C2054482} (本地连接* 10)                                                    2. \Device\NPF_{3E84CC27-C72B-4A70-9191-AE6A89A6FC61} (本地连接* 9)                                                     3. \Device\NPF_{7FB6DB96-53B3-4EBC-B751-F7387E732C52} (本地连接* 8)                                                     4. \Device\NPF_{E0FCC34A-5735-493B-A47B-420EABA1453D} (蓝牙网络连接 2)                                                  5. \Device\NPF_{8267309B-D360-4CD1-83FB-6A399A91CAD3} (WLAN 3)                                                          6. \Device\NPF_{8058E40F-1994-4C75-93DA-A3FE43A854CD} (本地连接* 13)                                                    7. \Device\NPF_{9308E9C9-5DEE-4BCB-BBDF-7547A9D2CB18} (本地连接* 12)                                                    8. \Device\NPF_Loopback (Adapter for loopback traffic capture)                                                          9. \\.\USBPcap1 (USBPcap1)                                                                                              10. \\.\USBPcap2 (USBPcap2)                                                                                             11. ciscodump (Cisco remote capture)                                                                                    12. etwdump (Event Tracing for Windows (ETW) reader)                                                                    13. randpkt (Random packet generator)                                                                                   14. sshdump.exe (SSH remote capture)                                                                                    15. udpdump (UDP Listener remote capture)                                                                               16. wifidump.exe (Wi-Fi remote capture)  
	2. C:\Windows\System32>tshark -i \Device\NPF_{8267309B-D360-4CD1-83FB-6A399A91CAD3} -F pcap -w capture.pcap -c 1000
		Capturing on 'WLAN 3'
		1000
	3. C:\Windows\System32>tshark -r capture.pcap -Y "tcp"
	    1   0.000000 192.168.6.197 → 140.207.55.20 TLSv1.2 788 Application Data
	    2   0.133738 140.207.55.20 → 192.168.6.197 TLSv1.2 425 Application Data
	    3   0.183670 192.168.6.197 → 140.207.55.20 TCP 54 52465 → 443 [ACK] Seq=735 Ack=372 Win=257 Len=0
	    6   1.539142 2408:873d:a00:3002::11 → 2408:8406:1980:27b:e9d9:48ef:7140:ddb2 TCP 115 8080 → 52503 [PSH, ACK] Seq=1 Ack=1 Win=2236 Len=41
	    7   1.541430 2408:8406:1980:27b:e9d9:48ef:7140:ddb2 → 2408:873d:a00:3002::11 TCP 449 52503 → 8080 [PSH, ACK] Seq=1 Ack=42 Win=254 Len=375
	    8   1.595858 2408:873d:a00:3002::11 → 2408:8406:1980:27b:e9d9:48ef:7140:ddb2 TCP 74 8080 → 52503 [ACK] Seq=42 Ack=376 Win=2257 Len=0
	    9   1.627503 2408:873d:a00:3002::11 → 2408:8406:1980:27b:e9d9:48ef:7140:ddb2 TCP 793 8080 → 52503 [PSH, ACK] Seq=42 Ack=376 Win=2257 Len=719
	   10   1.678671 2408:8406:1980:27b:e9d9:48ef:7140:ddb2 → 2408:873d:a00:3002::11 TCP 74 52503 → 8080 [ACK] Seq=376 Ack=761 Win=251 Len=0
	   11   4.180955 192.168.6.197 → 140.207.55.20 SSL 1414
	   12   4.180955 192.168.6.197 → 140.207.55.20 TLSv1.2 645 Application Data
	   13   4.269192 140.207.55.20 → 192.168.6.197 TCP 54 443 → 52463 [ACK] Seq=1 Ack=1952 Win=16725 Len=0
	   14   4.289590 140.207.55.20 → 192.168.6.197 TLSv1.2 426 Application Data
	   15   4.331639 192.168.6.197 → 140.207.55.20 TCP 54 52463 → 443 [ACK] Seq=1952 Ack=373 Win=258 Len=0
	   16   4.375651 192.168.6.197 → 192.168.6.95 TCP 66 55133 → 53 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
	   17   4.375919 192.168.6.197 → 192.168.6.95 TCP 66 55134 → 53 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
	   18   4.376077 192.168.6.197 → 192.168.6.95 TCP 66 55135 → 53 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
	   19   4.376487 192.168.6.197 → 111.206.210.98 SSL 1414
	   20   4.376487 192.168.6.197 → 111.206.210.98 TLSv1.2 1100 Application Data
	   21   4.376544 192.168.6.197 → 111.206.210.98 TLSv1.2 128 Application Data
	   22   4.384476 192.168.6.95 → 192.168.6.197 TCP 66 53 → 55135 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 SACK_PERM WS=256
	   .........
	   4. C:\Windows\System32>tshark -r capture.pcap -q -z io,phs
		===============================================================
			Protocol Hierarchy Statistics
			Filter:
			
			eth                                      frames:1000 bytes:299734
			  ip                                     frames:888 bytes:235036
			    tcp                                  frames:818 bytes:202266
			      tls                                frames:180 bytes:121848
			        tcp.segments                     frames:40 bytes:32457
			          tls                            frames:11 bytes:9969
			      dns                                frames:71 bytes:9952
			        tcp.segments                     frames:71 bytes:9952
			    udp                                  frames:58 bytes:31606
			      dns                                frames:24 bytes:3039
			      quic                               frames:34 bytes:28567
			        quic                             frames:2 bytes:2584
			    icmp                                 frames:12 bytes:1164
			  arp                                    frames:2 bytes:84
			  ipv6                                   frames:110 bytes:64614
			    tcp                                  frames:50 bytes:14574
			      http                               frames:4 bytes:2542
			        data                             frames:4 bytes:2542
			      tls                                frames:1 bytes:75
			    udp                                  frames:60 bytes:50040
			      gquic                              frames:60 bytes:50040
			===================================================================