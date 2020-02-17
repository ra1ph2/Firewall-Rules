# Firewall-Rules
Basic Firewall Rules implemented in Prolog for partial fulfilment of CS F214 (Logic in Computer Science)
This is Prolog knowledge base for Problem 1 - Firewall Rules made by Akshit Khanna (2017A7PS0023P) and Naman singhal(2017A7PS0181P) .

## Problem Statement

The problem statement was to build a firewall in prolog that uses Adapter,Ethernet and IPv4 clauses to evaluate if a packet is to be accepted, rejected or dropped .
Our implementation has assumed that to reject and accept a packet all the clauses must evaluate to true and otherwise the packet is dropped silently and the query returns false . All the database ranges used to check the conditions are taken to be mutually exclusive . The TCP and UDP ports are assumed to operate on different ports and hence are taken in OR in the main predicate . 

Accept returns 'Package Accepted' true
Reject returns 'Package Rejected' true
Drop returns false

The common input variables used in in knowledge base are :- 
	- Adp- Adapter (Char)
	- Vid- Virtual LAN Number(Number)
	- Proto- Protocol(String)
	- Src- Source IP(String)
	- Dest- Destination IP(String)
	- SPort- Source Port Number(Number)
	- DPort- Destination Port Number(Number)
	- Action- Placeholder variable to keep track of results of various 			  predicates for accept and reject conditions 
	- N1,N2,N3,N4 - Part of IP address after being parsed
      
## Predicates :-

packetFirewall(Adp,Vid,Proto,Src,Dest,SPort,DPort)
	-This is the main predicate use to output the result
	-Used twice to check for TCP OR UDP ports .
		
adapter(Adp,Action)
	-Wrapper predicate for Database predicate ad_DB .
	
ethernet(Proto,Vid,Action)
	-Wrapper predicate for Database predicate eth_DB

srcTcpCheck(Src,SPort,Action)
	-Wrapper predicate for Database predicate ip_DB_srcTcp
	-Calls parseIP predicate

destTcpCheck(Dest,DPort,Action)
	-Wrapper predicate for Database predicate ip_DB_destTcp
	-Calls parseIP predicate

srcUdpCheck(Src,SPort,Action)
	-Wrapper predicate for Database predicate ip_DB_srcTcp
	-Calls parseIP predicate

destTcpCheck(Dest,DPort,Action)
	-Wrapper predicate for Database predicate ip_DB_destTcp
	-Calls parseIP predicate

parseIP(N1,N2,N3,N4,Src) 
	-Parses the IP address (string) into numbers
	-Uses inbuilt predicates atomic_list_concat , atom_number and nth1 

checkReAction(Action) 
	-Checks if Action variable is same as intialized in the first reject 		 condition and returns true 
	-If it is not true then calls drop() to signify the some clause is not true 		 in accept range and therefore the packet is to be dropped

checkApAction(Action) 
	-Checks if Action variable is same as intialized in the first accept 		 condition and returns 
	-If it is not true then calls drop() to signify the some clause is not true 		 in accept range and therefore the packet is to be dropped 

reject()
	-Prints 'Packet Rejected' when all the clauses staify reject conditions

accept()
	-Prints 'Packet Accepted' when all the clauses staify accept conditions

drop()
	-Just return false to break the predicates and to eventually return false 		 without any text printed

bounds(Y,K,L)
	-Predicate for repeated range comparisons in the Database predicates

protoRe()
	-Used to stores facts about protocols to be rejected

protoDr()
	-Used to stores facts about protocols to be dropped

protoAc()
	-Used to stores facts about protocols to be accepted

ad_DB(Adp,Action)
	-Three definitions for the different actions
	-Checks Adapter clause conditions

eth_DB(Proto,Vid,Action)
	-Three definitions for the different actions
	-Checks Ethernet clause conditions

ip_DB_srcTcp(N1,N2,N3,N4,SPort,Action)
	-Three definitions for the different actions
	-Checks IP source clause conditions for TCP port

ip_DB_destTcp(N1,N2,N3,N4,DPort,Action)
	-Three definitions for the different actions
	-Checks IP destination clause conditions for TCP port
	-Only predicate to call accept() or reject() after checking all the previous 		 clause results with Action variable

ip_DB_srcUdp(N1,N2,N3,N4,SPort,Action)
	-Three definitions for the different actions
	-Checks IP source clause conditions for UDP port

ip_DB_destUdp(N1,N2,N3,N4,DPort,Action)
	-Three definitions for the different actions
	-Checks IP destination clause conditions for TCP port
	-Only predicate to call accept() or reject() after checking all the previous 		 clause results with Action variable

## Database

Reject Condition Ranges -
	-Adapter - 'G' to 'L'
	-Ethernet - Vid 1 to 335
		  - Proto(arp|aarp|atalk|ipx)
	-IP - Src 172.17.35.12 to 23
	    - Dest 172.17.52.17 to 35
	    - SPort 300 to 420 (TCP)  721 to 850 (UDP)
	    - DPort 1500 to 1700 (TCP)  2201 to 2400 (UDP)

Accept Condition Ranges - 
	-Adapter - 'A' to 'F'
	-Ethernet - Vid 460 to 999
		  - Proto(pppoe|rarp|sna|xns)
	-IP - Src 172.17.35.80 to 99
	    - Dest 172.17.52.61 to 99
	    - SPort 541 to 720 (TCP)  921 to 1030 (UDP)
   	    - DPort 1901 to 2200 (TCP) 2701 to 3000 (UDP)

Drop Condition Ranges -
	-Adapter - 'M' to 'P'
	-Ethernet - Vid 336 to 459
		  - Proto(mpls|netbui)
	-IP - Src 172.17.35.24 to 79
	    - Dest 172.17.52.35 to 60 
	    - SPort 421 to 540 (TCP) 851 to 920 (UDP)
	    - DPort 1701 to 1900 (TCP) 2401 to 2700 (UDP)

All the other inputs apart from the ranges specified default to drop condition .
