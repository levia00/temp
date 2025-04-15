### spanning tree protocol
Switch0:
Switch>en 
Switch#show spanning-tree 
Switch#config ter 
Switch(config)#interface fa0/2 
Switch(config-if)#shut  
Switch(config-if)#exit 
Switch(config)#exit 
Switch 1:
Switch>en 
Switch#show spanning-tree 
Switch>en 
Switch#show spanning-tree VLAN0001 
Switch#config ter 
Switch(config)#spanning-tree vlan 1 ? priority Set the 
bridge priority for the spanning tree root 
Configure switch as root 
Switch(config)#spanning-tree vlan 1? 
Switch(config)#spanning-tree vlan 1 ? 
Switch(config)#spanning-tree vlan 1 root ? primary Configure this  
Switch(config)#spanning-tree vlan 1 root primary 
Switch(config)#exit 