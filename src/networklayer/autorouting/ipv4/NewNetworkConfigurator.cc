//
// Copyright (C) 2011 Opensim Ltd
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <set>
#include <algorithm>
#include "IRoutingTable.h"
#include "IInterfaceTable.h"
#include "IPvXAddressResolver.h"
#include "NewNetworkConfigurator.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"


Define_Module(NewNetworkConfigurator);

void NewNetworkConfigurator::initialize(int stage)
{
    if (stage==2)
    {
        cTopology topo("topo");
        NetworkInfo networkInfo;

        // extract topology into the cTopology object, then fill in a LinkInfo[] vector
        extractTopology(topo, networkInfo);

        // assign addresses to IPv4 nodes
        assignAddresses(topo, networkInfo);

        // check IP address uniqueness over the network, and that all subnets live on a single link
        checkAddresses(topo, networkInfo);

        if (par("addStaticRoutes").boolValue()) {
            // add default routes to hosts (nodes with a single attachment);
            // also remember result in nodeInfo[].usesDefaultRoute
            if (par("useDefaultRoutes").boolValue())
                addDefaultRoutes(topo, networkInfo);

            // calculate shortest paths, and add corresponding static routes
            fillRoutingTables(topo, networkInfo);
        }

        // TODO: optimize routing tables based on the following operations:
        // - check if two subsequent routes can be swapped
        // - check if two subsequent routes complement each other
        // - check if a route is covered by the following one

        // dump(networkInfo);
    }
}

static cTopology::LinkOut *findLinkOut(cTopology::Node *node, int gateId)
{
	for (int i=0; i<node->getNumOutLinks(); i++)
		if (node->getLinkOut(i)->getLocalGateId() == gateId)
			return node->getLinkOut(i);
	return NULL;
}

void NewNetworkConfigurator::extractTopology(cTopology& topo, NetworkInfo& networkInfo)
{
    // extract topology
    topo.extractByProperty("node");
    EV << "cTopology found " << topo.getNumNodes() << " nodes\n";

    // extract nodes, fill in isIPNode, ift and rt members in nodeInfo[]
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        cTopology::Node *node = topo.getNode(i);
        cModule *mod = node->getModule();
        NodeInfo *nodeInfo = new NodeInfo();
        networkInfo.nodes[node] = nodeInfo;
        nodeInfo->isIPNode = IPvXAddressResolver().findInterfaceTableOf(mod)!=NULL;
        if (nodeInfo->isIPNode)
        {
            nodeInfo->ift = IPvXAddressResolver().interfaceTableOf(mod);
            nodeInfo->rt = IPvXAddressResolver().routingTableOf(mod);
        }
    }

    // extract links and interfaces
    std::set<InterfaceEntry*> interfacesSeen;
    for (int i = 0; i < topo.getNumNodes(); i++)
    {
    	cModule *mod = topo.getNode(i)->getModule();
    	IInterfaceTable *ift = IPvXAddressResolver().findInterfaceTableOf(mod);
    	if (ift)
    	{
    		for (int j = 0; j < ift->getNumInterfaces(); j++)
    		{
    			InterfaceEntry *ie = ift->getInterface(j);
    			if (!ie->isLoopback() && interfacesSeen.count(ie) == 0)  // "not yet seen"
    			{
    				// store interface as belonging to a new network link
			        networkInfo.links.push_back(new LinkInfo());
			        LinkInfo* linkInfo = networkInfo.links.back();
			        linkInfo->interfaces.push_back(new InterfaceInfo(ie));
    				interfacesSeen.insert(ie);

    				// visit neighbor (and potentially the whole LAN, recursively)
    				cTopology::LinkOut *linkOut = findLinkOut(topo.getNode(i), ie->getNodeOutputGateId());
    				if (linkOut)
    				{
				        std::vector<cTopology::Node*> empty;
				        visitNeighbor(linkOut, linkInfo, interfacesSeen, empty);
    				}
    			}
    		}
    	}
    }
}

template<typename T>
inline typename std::vector<T>::iterator find(std::vector<T>& v, T& a) {return std::find(v.begin(), v.end(), a);}

template<typename T>
inline bool contains(std::vector<T>& v, T& a) {return find(v, a) != v.end();}

void NewNetworkConfigurator::visitNeighbor(cTopology::LinkOut *linkOut, LinkInfo* linkInfo,
		std::set<InterfaceEntry*>& interfacesSeen, std::vector<cTopology::Node*>& deviceNodesVisited)
{
    cModule *neighborMod = linkOut->getRemoteNode()->getModule();
    int neighborInputGateId = linkOut->getRemoteGateId();
    IInterfaceTable *neighborIft = IPvXAddressResolver().findInterfaceTableOf(neighborMod);
    if (neighborIft)
    {
        // neighbor is a host or router, just add the interface
        InterfaceEntry *neighborIe = neighborIft->getInterfaceByNodeInputGateId(neighborInputGateId);
		if (interfacesSeen.count(neighborIe) == 0)  // "not yet seen"
		{
	        linkInfo->interfaces.push_back(new InterfaceInfo(neighborIe));
	        interfacesSeen.insert(neighborIe);
		}
    }
    else
    {
        // assume that neighbor is an L2 or L1 device (bus/hub/switch/bridge/access point/etc); visit all its output links
        cTopology::Node *deviceNode = linkOut->getRemoteNode();
        if (!contains(deviceNodesVisited, deviceNode))
        {
        	deviceNodesVisited.push_back(deviceNode);
        	for (int i = 0; i < deviceNode->getNumOutLinks(); i++)
        	{
        		cTopology::LinkOut *deviceLinkOut = deviceNode->getLinkOut(i);
        		visitNeighbor(deviceLinkOut, linkInfo, interfacesSeen, deviceNodesVisited);
        	}
        }
    }
}

void NewNetworkConfigurator::handleMessage(cMessage *msg)
{
    error("this module doesn't handle messages, it runs only in initialize()");
}

void NewNetworkConfigurator::dump(const NetworkInfo& networkInfo)
{
	for (int i = 0; i < networkInfo.links.size(); i++)
	{
		EV << "Link " << i << "\n";
	    const LinkInfo* linkInfo = networkInfo.links[i];
		for (int j = 0; j < linkInfo->interfaces.size(); j++)
		{
			const InterfaceEntry *ie = linkInfo->interfaces[j]->entry;
			cModule *host = dynamic_cast<cModule *>(ie->getInterfaceTable())->getParentModule();
			EV << "    " << host->getFullName() << " / " << ie->getName() << " " << ie->info() << "\n";
		}
	}
}

void NewNetworkConfigurator::assignAddresses(cTopology& topo, NetworkInfo& networkInfo)
{
    // iterate through all links and assign addresses
    for (int linkIndex = 0; linkIndex < networkInfo.links.size(); linkIndex++) {
        LinkInfo *selectedLink = networkInfo.links.at(linkIndex);
        // repeat until all interfaces of the selected link become configured
        std::vector<InterfaceInfo*> unconfiguredInterfaces = selectedLink->interfaces;
        while (unconfiguredInterfaces.size() != 0) {
            std::vector<InterfaceInfo*> compatibleInterfaces;
            // find a subset of the unconfigured interfaces that have compatible address and netmask specifications.
            // determine the merged address and netmask specifications according to the following table.
            // the '?' symbol means the bit is unspecified, the 'X' symbol means the bit is incompatible.
            // | * | 0 | 1 | ? |
            // | 0 | 0 | X | 0 |
            // | 1 | X | 1 | 1 |
            // | ? | 0 | 1 | ? |
            uint32 mergedAddress = 0;
            uint32 mergedAddressSpecifiedBits = 0;
            uint32 mergedAddressIncompatibleBits = 0;
            uint32 mergedNetmask = 0;
            uint32 mergedNetmaskSpecifiedBits = 0;
            uint32 mergedNetmaskIncompatibleBits = 0;
            for (int unconfiguredInterfaceIndex = 0; unconfiguredInterfaceIndex < unconfiguredInterfaces.size(); unconfiguredInterfaceIndex++) {
                InterfaceInfo *candidateInterface = unconfiguredInterfaces.at(unconfiguredInterfaceIndex);
                // extract candidate data
                uint32 candidateAddress = candidateInterface->address.getInt();
                uint32 candidateAddressSpecifiedBits = candidateInterface->addressSpecifiedBits;
                uint32 candidateNetmask = candidateInterface->netmask.getInt();
                uint32 candidateNetmaskSpecifiedBits = candidateInterface->netmaskSpecifiedBits;
//                System.out.println("Trying to merge candidate address: " + new IPAddress(candidateAddress) + " / " + new IPAddress(candidateAddressSpecifiedBits));
//                System.out.println("Trying to merge candidate netmask: " + new IPAddress(candidateNetmask) + " / " + new IPAddress(candidateNetmaskSpecifiedBits));
                // determine merged netmask
                uint32 commonNetmaskSpecifiedBits = mergedNetmaskSpecifiedBits & candidateNetmaskSpecifiedBits;
                uint32 newMergedNetmask = mergedNetmask | (candidateNetmask & candidateNetmaskSpecifiedBits);
                uint32 newMergedNetmaskSpecifiedBits = mergedNetmaskSpecifiedBits | candidateNetmaskSpecifiedBits;
                uint32 newMergedNetmaskIncompatibleBits = mergedNetmaskIncompatibleBits | ((mergedNetmask & commonNetmaskSpecifiedBits) ^ (candidateNetmask & commonNetmaskSpecifiedBits));
                // skip interface if there's a bit where the netmasks are incompatible
                if (newMergedNetmaskIncompatibleBits != 0)
                    continue;
                // determine merged address
                uint32 commonAddressSpecifiedBits = mergedAddressSpecifiedBits & candidateAddressSpecifiedBits;
                uint32 newMergedAddress = mergedAddress | (candidateAddress & candidateAddressSpecifiedBits);
                uint32 newMergedAddressSpecifiedBits = mergedAddressSpecifiedBits | candidateAddressSpecifiedBits;
                uint32 newMergedAddressIncompatibleBits = mergedAddressIncompatibleBits | ((mergedAddress & commonAddressSpecifiedBits) ^ (candidateAddress & commonAddressSpecifiedBits));
                // skip interface if there's a bit where the netmask is 1 and the addresses are incompatible
                if ((newMergedNetmask & newMergedNetmaskSpecifiedBits & newMergedAddressIncompatibleBits) != 0)
                    continue;
                // skip interface if there's a bit where the address is specified, incompatible and the netmask is 1
                // TODO: do we really need to & newMergedNetmask & newMergedNetmaskSpecifiedBits?????
                if ((newMergedAddressSpecifiedBits & newMergedAddressIncompatibleBits & newMergedNetmask & newMergedNetmaskSpecifiedBits) != 0)
                    continue;
                // add interface to the list of compatible interfaces
                compatibleInterfaces.push_back(candidateInterface);
                mergedAddress = newMergedAddress;
                mergedAddressSpecifiedBits = newMergedAddressSpecifiedBits;
                mergedAddressIncompatibleBits = newMergedAddressIncompatibleBits;
                mergedNetmask = newMergedNetmask;
                mergedNetmaskSpecifiedBits = newMergedNetmaskSpecifiedBits;
                mergedNetmaskIncompatibleBits = newMergedNetmaskIncompatibleBits;
//                System.out.println("Merged address specification: " + new IPAddress(mergedAddress) + " / " + new IPAddress(mergedAddressSpecifiedBits) + " / " + new IPAddress(mergedAddressIncompatibleBits));
//                System.out.println("Merged netmask specification: " + new IPAddress(mergedNetmask) + " / " + new IPAddress(mergedNetmaskSpecifiedBits) + " / " + new IPAddress(mergedNetmaskIncompatibleBits));
            }
//            System.out.println("Found " + compatibleInterfaces.size() + " compatible interfaces");
            // determine the valid range of netmask length
            int minNetmaskLength = 0;
            int maxNetmaskLength = 32;
            for (int bitIndex = 31; bitIndex >= 0; bitIndex--) {
                uint32 mask = 1 << bitIndex;
                if ((mergedNetmaskSpecifiedBits & mask) != 0) {
                    if ((mergedNetmask & mask) != 0)
                        minNetmaskLength = std::max(minNetmaskLength, 32 - bitIndex);
                    else
                        maxNetmaskLength = std::min(maxNetmaskLength, 31 - bitIndex);
                }
                if ((mergedAddressIncompatibleBits & mask) != 0)
                    maxNetmaskLength = std::min(maxNetmaskLength, 31 - bitIndex);
            }
            // make sure there are enough bits to configure a unique address for all interface (+ 2 means that all 1 and all 0 addresses are ruled out)
            int interfaceAddressBitCount = (int)std::ceil(std::log((double)(compatibleInterfaces.size() + 2)) / std::log((double)2));
            maxNetmaskLength = std::min(maxNetmaskLength, 32 - interfaceAddressBitCount);
//            System.out.println("Netmask valid length range: " + minNetmaskLength + " - " + maxNetmaskLength);
            // determine network address and network netmask
            int netmaskLength;
            uint32 networkAddress = 0;
            uint32 networkNetmask = 0;
            for (netmaskLength = maxNetmaskLength; netmaskLength >= minNetmaskLength; netmaskLength--) {
                networkNetmask = ((1 << netmaskLength) - 1) << (32 - netmaskLength);
                networkAddress = mergedAddress & mergedAddressSpecifiedBits & networkNetmask;
                uint32 networkAddressUnspecifiedBits = ~mergedAddressSpecifiedBits & networkNetmask;
                // TODO: for the sake of simplicity we assume a continuous range of unspecified bits
                //       otherwise we would have to add 1 to the max value in an integer where bits are scattered
                int last1BitIndex = 0;
                for (int bitIndex = 31; bitIndex >= 0; bitIndex--) {
                    uint32 mask = 1 << bitIndex;
                    if ((networkAddressUnspecifiedBits & mask) != 0)
                        last1BitIndex = bitIndex;
                }
                uint32 max = 0;
                for (int addressIndex = 0; addressIndex < networkInfo.getNetworkAddresses().size(); addressIndex++) {
                    uint32 addressPrefix = networkInfo.getNetworkAddresses().at(addressIndex).getInt();
                    if ((addressPrefix & networkAddressUnspecifiedBits) > max)
                        max = addressPrefix & networkAddressUnspecifiedBits;
                }
                uint32 increment = networkInfo.getNetworkAddresses().size() == 0 ? 0 : 1 << last1BitIndex;
                networkAddress |= (max + increment) & networkAddressUnspecifiedBits;
                if (networkInfo.isUniqueAddressPrefix(IPv4Address(networkAddress), IPv4Address(networkNetmask)))
                    break;
            }
//            System.out.println("Selected netmask length: " + netmaskLength);
//            System.out.println("Selected network address: " + new IPAddress(networkAddress));
//            System.out.println("Selected network netmask: " + new IPAddress(networkNetmask));
            // determine addresses for all interfaces
            for (int interfaceIndex = 0; interfaceIndex < compatibleInterfaces.size(); interfaceIndex++) {
                InterfaceInfo *compatibleInterface = compatibleInterfaces.at(interfaceIndex);
                uint32 interfaceAddress = compatibleInterface->address.getInt();
                uint32 interfaceAddressSpecifiedBits = compatibleInterface->addressSpecifiedBits;
                uint32 interfaceAddressUnspecifiedBits = ~interfaceAddressSpecifiedBits & ~networkNetmask;
                // TODO: for the sake of simplicity we assume a continuous range of unspecified bits
                //       otherwise we would have to add 1 to the max value in an integer where bits are scattered
                int last1BitIndex = 0;
                for (int bitIndex = 31; bitIndex >= 0; bitIndex--) {
                    uint32 mask = 1 << bitIndex;
                    if ((interfaceAddressUnspecifiedBits & mask) != 0)
                        last1BitIndex = bitIndex;
                }
                uint32 max = 0;
                for (int otherInterfaceIndex = 0; otherInterfaceIndex < interfaceIndex; otherInterfaceIndex++) {
                    uint32 otherInterfaceAddress = compatibleInterfaces.at(otherInterfaceIndex)->address.getInt();
                    if ((otherInterfaceAddress & interfaceAddressUnspecifiedBits) > max)
                        max = otherInterfaceAddress & interfaceAddressUnspecifiedBits;
                }
                // start from 1 to avoid all 0 addresses
                uint32 increment = interfaceIndex == 0 ? 1 : 1 << last1BitIndex;
                interfaceAddress = (interfaceAddress & ~networkNetmask) | (max + increment) & interfaceAddressUnspecifiedBits;
                // configure interface
                // TODO: we should not create a new one here
                IPv4InterfaceData *interfaceData = new IPv4InterfaceData();
                IPv4Address address = IPv4Address(networkAddress | interfaceAddress);
                IPv4Address netmask = IPv4Address(networkNetmask);
                interfaceData->setIPAddress(address);
                interfaceData->setNetmask(netmask);
                compatibleInterface->address = address;
                compatibleInterface->entry->setIPv4Data(interfaceData);
                // remove configured interface
                unconfiguredInterfaces.erase(find(unconfiguredInterfaces, compatibleInterface));
            }
            // register the network address and netmask as being used
            networkInfo.addAddressPrefix(IPv4Address(networkAddress), IPv4Address(networkNetmask));
        }
    }
}

void NewNetworkConfigurator::checkAddresses(cTopology& topo, NetworkInfo& networkInfo)
{
    std::map<IPv4Address, InterfaceEntry *> addresses;
    for (int linkIndex = 0; linkIndex < networkInfo.links.size(); linkIndex++) {
        LinkInfo *selectedLink = networkInfo.links.at(linkIndex);
        for (int interfaceIndex = 0; interfaceIndex < selectedLink->interfaces.size(); interfaceIndex++) {
            InterfaceInfo *selectedInterface = selectedLink->interfaces.at(interfaceIndex);
            IPv4Address address = selectedInterface->entry->ipv4Data()->getIPAddress();
            if (addresses.find(address) != addresses.end())
                error("failed to configure unique IP addresses");
            addresses[address] = selectedInterface->entry;
        }
    }
    // TODO: check that all subnets live on a single link
}

void NewNetworkConfigurator::addDefaultRoutes(cTopology& topo, NetworkInfo& networkInfo)
{
    // add default route to nodes with exactly one (non-loopback) interface
    std::map<cTopology::Node*, NodeInfo*>& nodes = networkInfo.nodes;
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        cTopology::Node *node = topo.getNode(i);
        NodeInfo *nodeInfo = networkInfo.nodes[node];

        // skip bus types
        if (!nodeInfo->isIPNode)
            continue;

        IInterfaceTable *ift = nodeInfo->ift;
        IRoutingTable *rt = nodeInfo->rt;

        // count non-loopback interfaces
        int numIntf = 0;
        InterfaceEntry *ie = NULL;
        for (int k=0; k<ift->getNumInterfaces(); k++)
            if (!ift->getInterface(k)->isLoopback())
                {ie = ift->getInterface(k); numIntf++;}

        nodeInfo->usesDefaultRoute = (numIntf==1);
        if (numIntf!=1)
            continue; // only deal with nodes with one interface plus loopback

        EV << "  " << node->getModule()->getFullName() << " has only one (non-loopback) interface, adding default route\n";

        // NOTE: we don't specify the gateway in the default route which may result in extra ARP requests
        IPv4Route *route = new IPv4Route();
        route->setHost(IPv4Address());
        route->setNetmask(IPv4Address());
        route->setInterface(ie);
        route->setType(IPv4Route::REMOTE);
        route->setSource(IPv4Route::MANUAL);
        rt->addRoute(route);
    }
}

void NewNetworkConfigurator::fillRoutingTables(cTopology& topo, NetworkInfo& networkInfo)
{
    // fill in routing tables with static routes
    for (int i=0; i<topo.getNumNodes(); i++)
    {
        cTopology::Node *destNode = topo.getNode(i);
        NodeInfo *destNodeInfo = networkInfo.nodes[destNode];

        // skip bus types
        if (!destNodeInfo->isIPNode)
            continue;

        std::string destModName = destNode->getModule()->getFullName();
        IInterfaceTable *destIFT = destNodeInfo->ift;

        // calculate shortest paths from everywhere towards destNode
        topo.calculateUnweightedSingleShortestPathsTo(destNode);

        // add route (with host=destNode) to every routing table in the network
        // (excepting nodes with only one interface -- there we'll set up a default route)
        for (int j=0; j<topo.getNumNodes(); j++)
        {
            cTopology::Node *sourceNode = topo.getNode(j);
            NodeInfo *sourceNodeInfo = networkInfo.nodes[sourceNode];

            if (i==j || !sourceNodeInfo->isIPNode)
                continue;
            if (sourceNode->getNumPaths()==0)
                continue; // not connected
            if (sourceNodeInfo->usesDefaultRoute)
                continue; // already added default route here

            // find source output interface
            IInterfaceTable *sourceIFT = sourceNodeInfo->ift;
            int sourceGateId = sourceNode->getPath(0)->getLocalGateId();
            InterfaceEntry *sourceInterface = sourceIFT->getInterfaceByNodeOutputGateId(sourceGateId);
            ASSERT(sourceInterface);

            // find next hop input interface
            cTopology::LinkOut *link = sourceNode->getPath(0);
            while (!networkInfo.nodes[link->getRemoteNode()]->isIPNode)
                link = link->getRemoteNode()->getPath(0);

            IInterfaceTable *nextHopIFT = networkInfo.nodes[link->getRemoteNode()]->ift;
            int nextHopGateId = link->getRemoteGateId();
            InterfaceEntry *nextHopInterface = nextHopIFT->getInterfaceByNodeInputGateId(nextHopGateId);
            ASSERT(nextHopInterface);

            // find destination input interface
            link = sourceNode->getPath(0);
            while (link->getRemoteNode() != destNode)
                link = link->getRemoteNode()->getPath(0);

            int destGateId = link->getRemoteGateId();
            InterfaceEntry *destInterface = destIFT->getInterfaceByNodeInputGateId(destGateId);
            ASSERT(destInterface);

            // add route
            IRoutingTable *rt = sourceNodeInfo->rt;
            IPv4Route *route = new IPv4Route();
            IPv4InterfaceData *ipv4Data = destInterface->ipv4Data();
            route->setHost(IPv4Address(ipv4Data->getIPAddress().getInt() & ipv4Data->getNetmask().getInt()));
            route->setNetmask(ipv4Data->getNetmask());
            route->setInterface(sourceInterface);
            route->setGateway(nextHopInterface->ipv4Data()->getIPAddress());
            route->setType(IPv4Route::DIRECT);
            route->setSource(IPv4Route::MANUAL);
            rt->addRoute(route);

            EV << sourceNode->getModule()->getFullName() << " -> " << destNode->getModule()->getFullName() << "   " << route->info() << endl;
        }
    }
}