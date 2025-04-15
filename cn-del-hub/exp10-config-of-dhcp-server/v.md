at router
en
conf ter
interface gigabitEthernet 0/0
ip address 192.168.10.1 255.255.255.0
no shut
exit
// same at other side with 192.168.20.1
 then in conf ter
 ip dhcp pool 10
 network 192.168.10.0 255.255.255.0
 default-router 192.168.10.1
 ip dhcp excluded-address 192.168.10.3 192.168.10.6
 // also for 20. with no excluded address
// choose dhcp at all pc
