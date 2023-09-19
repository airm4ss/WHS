## PCAP Programming
Network Security 과제


C, C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램
* Ethernet Header: src mac / dst mac
* IP Header: src ip / dst ip
* TCP Header: src port / dst port
* Message




실행
```
//컴파일
gcc -o pcap_program pcap_program.c -lcap
//실행
sudo ./pcap_program
