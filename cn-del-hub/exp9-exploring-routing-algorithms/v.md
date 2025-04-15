### link state routing
Router(config-if)#exit
Router(config)#router ospf 1
Router(config-router)#network 10.0.0.0 0.255.255.255 area 0
Router(config-router)#network 30.0.0.0 0.255.255.255 area 0
Router(config-router)#network 40.0.0.0 0.255.255.255 area 0
Router(config-router)#exit
Router(config)#exit
Router1 Configuration:-
Router(config-if)#exit
Router(config)#router ospf 1
Router(config-router)#network 30.0.0.0 0.255.255.255 area 0
Router(config-router)#network 20.0.0.0 0.255.255.255 area 0
Router(config-router)#network 50.0.0.0 0.255.255.255 area 0
Router(config-router)#exit
Router(config)#exit
Router2 Configuration:-
Router(config-if)#exit
Router(config)#router ospf 1
Router(config-router)#network 40.0.0.0 0.255.255.255 area 0
Router(config-router)#network 40.0.0.0 0.255.255.255 area 0
Router(config-router)#network 50.0.0.0 0.255.255.255 area 0
Router(config-router)#exit
Router(config)#exit
### distance vector routing
1) Router Configuration: (R0, R1, R2)
1. Click the Router 
2. Click Config
3. Select the Fast Ethernet
4. Type the IP and Subnet mask)
5. Port Status - ON
 
 2) Assign the IP Address in Each Router:
1. Open the Router0
2. Click the Option Config
3. Click the option Serial2/0
4. Enter the IP Address and Subnet mask (10.0.0.2, 255.0.0.0)
5. Change the Clock Rate (64000)
6. Switch on the Port Status
1. Open the Router1
2. Click the Option Config
3. Click the option Serial2/0
4. Enter the IP Address and Subnet mask (10.0.0.3, 255.0.0.0)
5. Change the Clock Rate (Not Set)
6. Switch on the Port Status
1. Open the Router1
2. Click the Option Config
3. Click the option Serial3/0
4. Enter the IP Address and Subnet mask (20.0.0.2, 255.0.0.0)
5. Change the Clock Rate (64000)
6. Switch on the Port Status
1. Open the Router2
2. Click the Option Config
3. Click the option Serial2/0
4. Enter the IP Address and Subnet mask (20.0.0.3, 255.0.0.0)
5. Change the Clock Rate (Not Set)
6. Switch on the Port Status