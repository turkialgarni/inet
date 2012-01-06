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
        LinkInfoVector linkInfoVector;

        // extract topology into the cTopology object, then fill in a LinkInfo[] vector
        extractTopology(topo, linkInfoVector);

        dump(linkInfoVector);
    }
}

static cTopology::LinkOut *findLinkOut(cTopology::Node *node, int gateId)
{
	for (int i=0; i<node->getNumOutLinks(); i++)
		if (node->getLinkOut(i)->getLocalGateId() == gateId)
			return node->getLinkOut(i);
	return NULL;
}

void NewNetworkConfigurator::extractTopology(cTopology& topo, LinkInfoVector& linkInfoVector)
{
    // extract topology
    topo.extractByProperty("node");
    EV << "cTopology found " << topo.getNumNodes() << " nodes\n";

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
			        linkInfoVector.push_back(LinkInfo());
			        LinkInfo& linkInfo = linkInfoVector.back();
			        linkInfo.interfaces.push_back(InterfaceInfo(ie));
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
inline bool contains(std::vector<T> v, T& a) {return std::find(v.begin(), v.end(), a) != v.end();}

void NewNetworkConfigurator::visitNeighbor(cTopology::LinkOut *linkOut, LinkInfo& linkInfo,
		std::set<InterfaceEntry*>& interfacesSeen, std::vector<cTopology::Node*>& deviceNodesVisited)
{
    cModule *neighborMod = linkOut->getRemoteNode()->getModule();
    int neighborInputGateId = linkOut->getRemoteGateId();
    IInterfaceTable *neighborIft = IPvXAddressResolver().findInterfaceTableOf(neighborMod);
    if (neighborIft)
    {
        // neighbor is a host or router, just add the interface
        InterfaceEntry *neighborIe = neighborIft->getInterfaceByNodeInputGateId(neighborInputGateId);
        linkInfo.interfaces.push_back(InterfaceInfo(neighborIe));
        interfacesSeen.insert(neighborIe);
    }
    else
    {
        // assume that neighbor is an L2 or L1 device (bus/hub/switch/bridge/access point/etc); visit all its output links
        cTopology::Node *deviceNode = linkOut->getRemoteNode();
        if (contains(deviceNodesVisited, deviceNode))
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

void NewNetworkConfigurator::dump(const LinkInfoVector& linkInfoVector)
{
	for (int i = 0; i < linkInfoVector.size(); i++)
	{
		EV << "Link " << i << "\n";
	    const LinkInfo& linkInfo = linkInfoVector[i];
		for (int j = 0; j < linkInfo.interfaces.size(); j++)
		{
			const InterfaceEntry *ie = linkInfo.interfaces[j].entry;
			cModule *host = dynamic_cast<cModule *>(ie->getInterfaceTable())->getParentModule();
			EV << "    " << host->getFullName() << " / " << ie->getName() << "\n";
		}
	}
}
