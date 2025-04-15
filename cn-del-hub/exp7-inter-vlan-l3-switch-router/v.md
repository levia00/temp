### l3 switch
At Both Switches
1. Enable
2. show vlan 
3. configure terminal 
4. vlan 10 
5. exit
6. vlan 20 
7. exit
8. show vlan 
9. interface fastEthernet 0/ [interface Number] 
10. switchport mode access 
11. switchport access vlan [vlan name] 
12. enable (On switch 1 and 2) 
13. configure terminal 
14. interface fastEthernet 0/ [interface Number] 
15. switchport mode trunk
At Multi-Layer Switch
16. enable
17. configure terminal
18. vlan 10
19. vlan 20
20. interface fastEthernet 0/ [interface Number]
21. switchport trunk encapsulation dot 1q
22. switchport mode trunk
23. exit
24. ip routing
25. interface vlan 10
26. ip address 72.0.10.100 255.255.255.0
27. no shutdown
28. interface vlan 20
29. ip address 72.0.20.100 255.255.255.0
30. no shutdown

### router
At Switches
1. Enable
2. show vlan 
3. configure terminal 
4. vlan 10 
5. vlan 20 
6. vlan 30
7. show vlan 
8. interface fastEthernet 0/ [interface Number] 
9. switchport mode access 
10. switchport access vlan [vlan name] 
11. enable (On switch 4) 
12. configure terminal 
13. interface fastEthernet 0/ [interface Number] 
14. switchport mode trunk
At Router
1. enable
2. configure terminal
3. interface gigabitEthernet 0/0.10
4. encapsulation dot1Q 10
5. ip address 72.0.10.100 255.255.255.0
6. exit
7. interface gigabitEthernet 0/0.20
8. encapsulation dot1Q 20
9. ip address 72.0.20.100 255.255.255.0
10. exit
11. interface gigabitEthernet 0/0.30
12. encapsulation dot1Q 30
13. ip address 72.0.30.100 255.255.255.0
14. exit
15. show ip interface brief
16. interface gigabitEthernet 0/0
17. no shut