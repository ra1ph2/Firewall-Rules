packetFirewall(Adp,Vid,Proto,Src,Dest,SPort,DPort) :-
    adapter(Adp,Action),
    ethernet(Proto,Vid,Action),
    srcTcpCheck(Src,SPort,Action),
    destTcpCheck(Dest,DPort,Action).

packetFirewall(Adp,Vid,Proto,Src,Dest,SPort,DPort) :-
    adapter(Adp,Action),
    ethernet(Proto,Vid,Action),
    srcUdpCheck(Src,SPort,Action),
    destUdpCheck(Dest,DPort,Action).

adapter(Adp,Action):-
    /* Wrapper predicate for Database predicate */
    ad_DB(Adp,Action).

ethernet(Proto,Vid,Action) :-
    /* Wrapper predicate for Database predicate */
    eth_DB(Proto,Vid,Action).

srcTcpCheck(Src,SPort,Action) :-
    /* Wrapper predicate for Database predicate */
    parseIP(N1,N2,N3,N4,Src),
    ip_DB_srcTcp(N1,N2,N3,N4,SPort,Action).

destTcpCheck(Dest,DPort,Action):-
    /* Wrapper predicate for Database predicate */
    parseIP(N1,N2,N3,N4,Dest),
    ip_DB_destTcp(N1,N2,N3,N4,DPort,Action).

srcUdpCheck(Src,SPort,Action) :-
    /* Wrapper predicate for Database predicate */
    parseIP(N1,N2,N3,N4,Src),
    ip_DB_srcUdp(N1,N2,N3,N4,SPort,Action).

destUdpCheck(Dest,DPort,Action):-
    /* Wrapper predicate for Database predicate */
    parseIP(N1,N2,N3,N4,Dest),
    ip_DB_destUdp(N1,N2,N3,N4,DPort,Action).

parseIP(N1,N2,N3,N4,Src) :-
    /*Parses the Src IP into numbers*/
    atomic_list_concat(L ,'.',Src),
    nth1(1,L,Ns1),
    atom_number(Ns1,N1),
    nth1(2,L,Ns2),
    atom_number(Ns2,N2),
    nth1(3,L,Ns3),
    atom_number(Ns3,N3),
    nth1(4,L,Ns4),
    atom_number(Ns4,N4).

/* Action is a placeholder variable to keep track of results of various predicates for accept and reject */

checkReAction(Action):-
    /* Keeps track of previous Reject conditions */
    Action =:= 1000 .

checkReAction(Action):-
    drop().

checkApAction(Action):-
    /* Keeps track of previous Accept conditions */
    Action =:= 3000.

checkApAction(Action):-
    drop().

reject():-
    /* All conditions must met requirements for Reject */
    format(' Packet Rejected ~n').

accept():-
    /* All conditions must met requirements for Accept */
    format(' Packet Accepted ~n').

drop():-
    /* Anything other then Accept and Reject and for out of bounds input */
    false().

bounds(Y,K,L):-
    /* Basic comparison abstraction */
    Y >= K,
    Y =< L.

/* Protocol Facts */

protoRe(arp).
protoRe(aarp).
protoRe(atalk).
protoRe(ipx).

protoDr(mpls).
protoDr(netbui).

protoAc(pppoe).
protoAc(rarp).
protoAc(sna).
protoAc(xns).

/* Database checking predicates */

ad_DB(Adp,Action):-
    /*Rejecting the Packet(adapter)*/
    char_code(Adp,Adp_num),
    bounds(Adp_num,71,75), /*Ascii value of 'G' & 'L'*/
    Action is 1000.

ad_DB(Adp,Action):-
    /*Dropping the Packet(adapter)*/
    char_code(Adp,Adp_num),
    bounds(Adp_num,76,80), /*Ascii value of 'M' & 'P'*/
    Action is 2000,
    drop().

ad_DB(Adp,Action):-
    /*Accepting the Packet(adapter)*/
    char_code(Adp,Adp_num),
    bounds(Adp_num,65,70), /*Ascii value of 'A' & 'F'*/
    Action is 3000.

eth_DB(Proto,Vid,Action):-
    /*Rejecting the Packet(ethernet)*/
    bounds(Vid,1,335),
    protoRe(Proto),
    checkReAction(Action).

eth_DB(Proto,Vid,Action):-
    /*Dropping the Packet(ethernet)*/
    bounds(Vid,336,459),
    protoDr(Proto),
    drop().

eth_DB(Proto,Vid,Action):-
    /*Accepting the Packet(ethernet)*/
    bounds(Vid,460,999),
    protoAc(Proto),
    checkApAction(Action).

ip_DB_srcTcp(N1,N2,N3,N4,SPort,Action):-
    /*Rejecting the Packet(IP TCP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,12,23),
    bounds(SPort,300,420),
    checkReAction(Action).

ip_DB_srcTcp(N1,N2,N3,N4,SPort,Action):-
    /*Dropping the Packet(IP TCP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,24,79),
    bounds(SPort,421,540).

ip_DB_srcTcp(N1,N2,N3,N4,SPort,Action):-
    /*Accepting the Packet(IP TCP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,80,99),
    bounds(SPort,541,720),
    checkApAction(Action).

ip_DB_destTcp(N1,N2,N3,N4,DPort,Action):-
    /*Rejecting the Packet(IP TCP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,17,34),
    bounds(DPort,1500,1700),
    checkReAction(Action),
    reject().

ip_DB_destTcp(N1,N2,N3,N4,DPort,Action):-
    /*Dropping the Packet(IP TCP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,35,60),
    bounds(DPort,1701,1900).

ip_DB_destTcp(N1,N2,N3,N4,DPort,Action):-
    /*Accepting the Packet(IP TCP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,61,99),
    bounds(DPort,1901,2200),
    checkApAction(Action),
    accept().

ip_DB_srcUdp(N1,N2,N3,N4,SPort,Action):-
    /*Rejecting the Packet(IP UDP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,12,23),
    bounds(SPort,721,850),
    checkReAction(Action).

ip_DB_srcUdp(N1,N2,N3,N4,SPort,Action):-
    /*Dropping the Packet(IP UDP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,24,79),
    bounds(SPort,851,920).

ip_DB_srcUdp(N1,N2,N3,N4,SPort,Action):-
    /*Accepting the Packet(IP UDP Source)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 35,
    bounds(N4,80,99),
    bounds(SPort,921,1030),
    checkApAction(Action).

ip_DB_destUdp(N1,N2,N3,N4,DPort,Action):-
    /*Rejecting the Packet(IP UDP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,17,34),
    bounds(DPort,2201,2400),
    checkReAction(Action),
    reject().

ip_DB_destUdp(N1,N2,N3,N4,DPort,Action):-
    /*Dropping the Packet(IP UDP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,35,60),
    bounds(DPort,2401,2700),
    drop().

ip_DB_destUdp(N1,N2,N3,N4,DPort,Action):-
    /*Accepting the Packet(IP UDP Destination)*/
    N1 =:= 172,
    N2 =:= 17,
    N3 =:= 52,
    bounds(N4,61,99),
    bounds(DPort,2701,3000),
    checkApAction(Action),
    accept().
