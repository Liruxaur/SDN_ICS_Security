from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI

# Create a Mininet instance
net = Mininet(controller=RemoteController, switch=OVSSwitch)

# Add external controller (Assuming the controller is running at 127.0.0.1:6653)
c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

# Add switches
switches = [net.addSwitch(f'ovs{i+1}') for i in range(100)]

# Add hosts and link each host to its own switch
hosts = [net.addHost(f'h{i+1}', ip=f'192.168.0.{i+1}/24') for i in range(100)]

for i in range(100):
    net.addLink(hosts[i], switches[i])

# Link switches to each other
for i in range(100):
    if i < 99:
        net.addLink(switches[i], switches[i+1])
    else:
        net.addLink(switches[i], switches[0], intfName1=f's{i}-eth{i+1}', intfName2=f's0-eth1')




# Build the network
net.build()

# Start the controller
c0.start()

# Start switches with the configured controller
net.start()

# Run the Mininet command line interface
CLI(net)

# Stop the network and cleanup
net.stop()

