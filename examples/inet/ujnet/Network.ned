//
// This program is property of its copyright holder. All rights reserved.
// 

package inet.examples.inet.ujnet;

import inet.networklayer.autorouting.ipv4.NewNetworkConfigurator;
import inet.nodes.ethernet.EtherSwitch;
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;


module Subnet
{
    @display("bgl=10;bgb=555,307;i=misc/cloud;is=vl");
    gates:
        inout ethg[];
    types:
        channel Link extends ned.DatarateChannel
        {
            datarate = 100Mbps;
        }
    submodules:
        switch: EtherSwitch {
            @display("p=335,160");
        }
        lonelyHost: StandardHost {
            @display("p=77,58");
        }
        host1: StandardHost {
            @display("p=206,110");
        }
        host2: StandardHost {
            @display("p=477,133");
        }
        host3: StandardHost {
            @display("p=213,239");
        }
    connections:
        lonelyHost.ethg++ <--> Link <--> ethg++;
        lonelyHost.ethg++ <--> Link <--> host1.ethg++;
        host1.ethg++ <--> Link <--> switch.ethg++;
        host2.ethg++ <--> Link <--> switch.ethg++;
        host3.ethg++ <--> Link <--> switch.ethg++;
        for i=1..sizeof(ethg) - 1 {
            switch.ethg++ <--> Link <--> ethg++;
        }
}

//
// Generated network with random topology (10 nodes, 20 edges, seed=100).
//
network Network
{
    parameters:
        @display("bgb=700,485;bgl=22");
    types:
        channel Link extends ned.DatarateChannel
        {
            datarate = 1Gbps;
        }
    submodules:
        configurator: NewNetworkConfigurator {
            @display("p=473,44");
            config = xml("\
            <root> \
                <interface hosts='r0' towards='r1' address='99.100.x.x' netmask='255.255.x.x'/> \
                <interface hosts='r8 r9' names='*' address='11.3.x.x' netmask='255.255.x.x'/> \
            </root> \
            ");
        }
        r0: Router {
            @display("p=335,251");
        }
        r1: Router {
            @display("p=391,318");
        }
        r2: Router {
            @display("p=402,212");
        }
        r3: Router {
            @display("p=352,386");
        }
        r4: Router {
            @display("p=462,254");
        }
        r5: Router {
            @display("p=272,431");
        }
        r6: Router {
            @display("p=233,282");
        }
        r7: Router {
            @display("p=462,364");
        }
        r8: Router {
            @display("p=509,194");
        }
        r9: Router {
            @display("p=423,431");
        }
        subnet: Subnet {
            @display("p=283,183");
        }
        subnet1: Subnet {
            @display("p=585,264");
        }
        subnet2: Subnet {
            @display("p=550,408");
        }
        subnet3: Subnet {
            @display("p=108,263");
        }
        switch: EtherSwitch {
            @display("p=638,348");
        }
    connections:
        r0.pppg++ <--> Link <--> r1.pppg++;
        r0.pppg++ <--> Link <--> r2.pppg++;
        r0.pppg++ <--> Link <--> r3.pppg++;
        r0.pppg++ <--> Link <--> r4.pppg++;
        r0.pppg++ <--> Link <--> r5.pppg++;
        r0.pppg++ <--> Link <--> r6.pppg++;
        r1.pppg++ <--> Link <--> r2.pppg++;
        r1.pppg++ <--> Link <--> r3.pppg++;
        r2.pppg++ <--> Link <--> r7.pppg++;
        r2.pppg++ <--> Link <--> r8.pppg++;
        r3.pppg++ <--> Link <--> r5.pppg++;
        r3.pppg++ <--> Link <--> r7.pppg++;
        r4.pppg++ <--> Link <--> r7.pppg++;
        r4.pppg++ <--> Link <--> r8.pppg++;
        r5.pppg++ <--> Link <--> r6.pppg++;
        r5.pppg++ <--> Link <--> r9.pppg++;
        r7.pppg++ <--> Link <--> r9.pppg++;
        r1.pppg++ <--> Link <--> r7.pppg++;
        subnet1.ethg++ <--> r8.ethg++;
        subnet1.ethg++ <--> r4.ethg++;
        subnet.ethg++ <--> r2.ethg++;
        subnet.ethg++ <--> r6.ethg++;
        subnet3.ethg++ <--> r6.ethg++;
        subnet2.ethg++ <--> r9.ethg++;
        subnet1.ethg++ <--> switch.ethg++;
        switch.ethg++ <--> subnet2.ethg++;
}
