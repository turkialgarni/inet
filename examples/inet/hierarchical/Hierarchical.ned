//
// This program is property of its copyright holder. All rights reserved.
// 

package inet.examples.inet.hierarchical;

import inet.networklayer.autorouting.ipv4.IPv4Configurator;
import inet.nodes.ethernet.Eth100G;
import inet.nodes.ethernet.Eth100M;
import inet.nodes.ethernet.Eth1G;
import inet.nodes.ethernet.EtherSwitch;
import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHost;


network Hierarchical
{
    parameters:
        int columns = default(3);
        int rows = default(3);
    types:
        module LAN
        {
            parameters:
                int numHosts = default(3);
                @display("i=misc/cloud;is=s");
            gates:
                inout ethg[];
            submodules:
                switch: EtherSwitch {
                    @display("is=s");
                }
                host[numHosts]: StandardHost {
                    @display("is=s");
                }
            connections:
                for i=0..numHosts-1 {
                    host[i].ethg++ <--> Eth100M <--> switch.ethg++;
                }
                for i=0..sizeof(ethg) - 1 {
                    switch.ethg++ <--> ethg++;
                }
        }

        module Area
        {
            parameters:
                int numAreas = default(3);
                @display("i=misc/cloud;is=s");
            gates:
                inout ethg[];
            submodules:
                lan[numAreas]: LAN;
                router[numAreas]: Router {
                    @display("is=s");
                }
            connections:
                for i=0..numAreas-1 {
                    router[i].ethg++ <--> Eth1G <--> router[(i+1)%numAreas].ethg++ if numAreas > 1;
                    router[i].ethg++ <--> Eth1G <--> lan[i].ethg++;
                }
                router[0].ethg++ <--> ethg++;
        }

    submodules:
        configurator: IPv4Configurator {
            @display("p=37,31");
            optimizeRoutes = true;
            dumpTopology = true;
            dumpAddresses = true;
            dumpRoutes = true;
            config = xmldoc("hierarchical.xml");
        }
        router[columns*rows]: Router {
            @display("p=115,103,matrix,$columns;is=s");
        }
        area[columns*rows]: Area;
    connections:
        for i=0..rows-1, for j=0..columns-1 {
            router[i*columns+j].ethg++ <--> Eth100G <--> router[(i+1)*columns+j].ethg++ if i!=rows-1;
            router[i*columns+j].ethg++ <--> Eth100G <--> router[i*columns+j+1].ethg++ if j!=columns-1;
        }
        for i=0..rows*columns-1 {
            router[i].ethg++ <--> Eth100G <--> area[i].ethg++;
        }
}
