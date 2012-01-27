//
// This program is property of its copyright holder. All rights reserved.
// 

package inet.examples.inet.ujnet;

import inet.networklayer.autorouting.ipv4.IPv4Configurator;
import inet.nodes.ethernet.EtherSwitch;
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;

module LAN
{
    @display("bgl=12;bgb=395,342;i=misc/cloud;is=vl");
    gates:
        inout ethg[];
    types:
        channel Link extends ned.DatarateChannel
        {
            datarate = 100Mbps;
        }
    submodules:
        switch: EtherSwitch {
            @display("p=206,163");
        }
        host1: StandardHost {
            @display("p=302,84;t=10.x.x.1");
        }
        host2: StandardHost {
            @display("p=263,271;t=10.x.x.2");
        }
        host3: StandardHost {
            @display("p=84,164;t=10.x.x.3");
        }
    connections:
        host1.ethg++ <--> Link <--> switch.ethg++;
        host2.ethg++ <--> Link <--> switch.ethg++;
        host3.ethg++ <--> Link <--> switch.ethg++;
        for i=0..sizeof(ethg) - 1 {
            switch.ethg++ <--> ethg++;
        }
}

module Area
{
    @display("bgl=12;bgb=506,453;i=misc/cloud;is=vl");
    gates:
        inout ethg[];
    types:
        channel Link extends ned.DatarateChannel
        {
            datarate = 1Gbps;
        }
    submodules:
        lan1: LAN {
            @display("p=391,86;t=10.x.1.x");
        }
        lan2: LAN {
            @display("p=391,355;t=10.x.2.x");
        }
        lan3: LAN {
            @display("p=106,355;t=10.x.3.x");
        }
        lan4: LAN {
            @display("p=106,86;t=10.x.4.x");
        }
        router1: Router {
            @display("p=250,87");
        }
        router2: Router {
            @display("p=391,219");
        }
        router3: Router {
            @display("p=250,356");
        }
        router4: Router {
            @display("p=106,219");
        }
    connections:
        lan1.ethg++ <--> Link <--> router1.ethg++;
        lan2.ethg++ <--> Link <--> router2.ethg++;
        lan3.ethg++ <--> Link <--> router3.ethg++;
        lan4.ethg++ <--> Link <--> router4.ethg++;
        router1.ethg++ <--> Link <--> router2.ethg++;
        router2.ethg++ <--> Link <--> router3.ethg++;
        router3.ethg++ <--> Link <--> router4.ethg++;
        router4.ethg++ <--> Link <--> router1.ethg++;
        router1.ethg++ <--> ethg++;
}

network Network
{
    parameters:
        @display("bgb=708,518;bgl=22");
    types:
        channel Link extends ned.DatarateChannel
        {
            datarate = 10Gbps;
        }
    submodules:
        configurator: IPv4Configurator {
            @display("p=37,31");
            optimizeRoutes = true;
            dumpAddresses = true;
            dumpRoutes = true;
            config = xmldoc("network.xml");
        }
        area11: Area {
            @display("p=261,80;t=10.11.x.x");
        }
        area12: Area {
            @display("p=426,80;t=10.12.x.x");
        }
        area21: Area {
            @display("p=581,299;t=10.21.x.x");
        }
        area22: Area {
            @display("p=426,432;t=10.22.x.x");
        }
        area31: Area {
            @display("p=104,299;t=10.31.x.x");
        }
        area32: Area {
            @display("p=261,432;t=10.32.x.x");
        }
        router1: Router {
            @display("p=337,196");
        }
        router2: Router {
            @display("p=426,300");
        }
        router3: Router {
            @display("p=261,300");
        }
    connections:
        router1.ethg++ <--> Link <--> router2.ethg++;
        router2.ethg++ <--> Link <--> router3.ethg++;
        router3.ethg++ <--> Link <--> router1.ethg++;
        router1.ethg++ <--> Link <--> area11.ethg++;
        router1.ethg++ <--> Link <--> area12.ethg++;
        router2.ethg++ <--> Link <--> area21.ethg++;
        router2.ethg++ <--> Link <--> area22.ethg++;
        router3.ethg++ <--> Link <--> area31.ethg++;
        router3.ethg++ <--> Link <--> area32.ethg++;
}
