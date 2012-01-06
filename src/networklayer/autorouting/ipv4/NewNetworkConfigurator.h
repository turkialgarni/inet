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

#ifndef __INET_NEWNETWORKCONFIGURATOR_H
#define __INET_NEWNETWORKCONFIGURATOR_H

#include <omnetpp.h>
#include "INETDefs.h"
#include "IPv4Address.h"

class IInterfaceTable;
class IRoutingTable;


/**
 * Configures IPv4 addresses for a network,
 *
 * For more info please see the NED file.
 */
class INET_API NewNetworkConfigurator : public cSimpleModule
{
  protected:
    struct InterfaceInfo {
    	InterfaceInfo(InterfaceEntry *ie) {entry = ie;}
    	InterfaceEntry *entry;
    };
    struct LinkInfo {
    	std::vector<InterfaceInfo> interfaces;
    };
    typedef std::vector<LinkInfo> LinkInfoVector;

  protected:
    virtual int numInitStages() const  {return 3;}
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);

    virtual void extractTopology(cTopology& topo, LinkInfoVector& linkInfo);
    virtual void visitNeighbor(cTopology::LinkOut *linkOut, LinkInfo& linkInfo, std::set<InterfaceEntry*>& interfacesSeen, std::vector<cTopology::Node*>& nodesVisited);
    void dump(const LinkInfoVector& linkInfoVector);
};

#endif

