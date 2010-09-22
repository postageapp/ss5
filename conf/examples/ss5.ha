# Define slave ss5 istances
#
peer 192.168.1.1

# Connections to 10.2.2 network are made using 192.168.1.100 as source ip
#
#     Host/Net    SrcIf           Group      s/d (s= source e' la /destination)
route 10.2.2.0/24 192.168.1.100   sysadmin   d

