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
namespace inet { class PatternMatcher; }


/**
 * Configures IPv4 addresses for a network.
 *
 * For more info please see the NED file.
 */
class INET_API NewNetworkConfigurator : public cSimpleModule
{
  protected:
    struct InterfaceInfo {
        bool configure;  //TODO code should obey it!
        InterfaceEntry *entry;
        IPv4Address address;
        uint32 addressSpecifiedBits;
        IPv4Address netmask;
        uint32 netmaskSpecifiedBits;
        InterfaceInfo(InterfaceEntry *ie) {
            configure = true;
            entry = ie;
            // NOTE: default IP addresses are in the subnet 10.x.x.x/255.255.x.x
            address = IPv4Address(0x0A000000);
            addressSpecifiedBits = 0xFF000000;
            netmask = IPv4Address(0xFFFF0000);
            netmaskSpecifiedBits = 0xFFFF0000;
        }
    };

    struct NodeInfo {
        NodeInfo() {module = NULL; isIPNode = false; ift = NULL; rt = NULL; usesDefaultRoute = false;}
        cModule *module;
        bool isIPNode;
        IInterfaceTable *ift;
        IRoutingTable *rt;
        bool usesDefaultRoute;
    };

    struct LinkInfo {
        std::vector<InterfaceInfo*> interfaces; // interfaces on that LAN or point-to-point link
        ~LinkInfo() { for (int i = 0; i < interfaces.size(); i++) delete interfaces[i]; }
    };

    struct NetworkInfo {  //TODO put cTopology* into it
        std::map<cTopology::Node*, NodeInfo*> nodes;
        std::vector<LinkInfo*> links;
        std::vector<IPv4Address> addresses;
        std::vector<IPv4Address> netmasks;
        ~NetworkInfo() { for (int i = 0; i < links.size(); i++) delete links[i]; }
        void addAddressPrefix(IPv4Address address, IPv4Address netmask) { addresses.push_back(address); netmasks.push_back(netmask); }
        std::vector<IPv4Address>& getNetworkAddresses() { return addresses; }
        bool isUniqueAddressPrefix(IPv4Address address, IPv4Address netmask)
        {
            for (int i = 0; i < addresses.size(); i++) {
                int commonNetmask = netmasks.at(i).getInt() & netmask.getInt();
                if ((addresses.at(i).getInt() & commonNetmask) == (address.getInt() & commonNetmask))
                    return false;
            }
            return true;
        }
    };

    class Matcher
    {
        private:
            bool matchesany;
            std::vector<inet::PatternMatcher*> matchers; // TODO replace with a MatchExpression once it becomes available in OMNeT++
        public:
            Matcher(const char *pattern);
            ~Matcher();
            bool matches(const char *s);
            bool matchesAny() {return matchesany;}
    };

  protected:
    virtual int numInitStages() const  {return 3;}
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);

    // main functionality
    virtual void extractTopology(cTopology& topo, NetworkInfo& networkInfo);
    virtual void readAddressConfiguration(cXMLElement *root, cTopology& topo, NetworkInfo& networkInfo);
    virtual void assignAddresses(cTopology& topo, NetworkInfo& networkInfo);
    virtual void checkAddresses(cTopology& topo, NetworkInfo& networkInfo);
    virtual void addDefaultRoutes(cTopology& topo, NetworkInfo& networkInfo);
    virtual void addManualRoutes(cXMLElement *root, NetworkInfo& networkInfo);
    virtual void fillRoutingTables(cTopology& topo, NetworkInfo& networkInfo);
    virtual void dump(const NetworkInfo& networkInfo);

    // helper functions
    virtual void parseAddressAndSpecifiedBits(const char *addressAttr, uint32_t& outAddress, uint32_t& outAddressSpecifiedBits);
    virtual bool linkContainsMatchingHostExcept(LinkInfo *linkInfo, Matcher *hostMatcher, cModule *exceptModule);
    virtual void visitNeighbor(cTopology::LinkOut *linkOut, LinkInfo* linkInfo, std::set<InterfaceEntry*>& interfacesSeen, std::vector<cTopology::Node*>& nodesVisited);
    const char *getMandatoryAttribute(cXMLElement *element, const char *attr);
    virtual void resolveInterfaceAndGateway(NodeInfo *node, const char *interfaceAttr, const char *gatewayAttr,
            InterfaceEntry *&outIE, IPv4Address& outGateway, const NetworkInfo& networkInfo);
    InterfaceInfo *findInterfaceOnLinkByNode(LinkInfo *linkInfo, cModule *node);
    InterfaceInfo *findInterfaceOnLinkByNodeAddress(LinkInfo *linkInfo, IPv4Address address);
    LinkInfo *findLinkOfInterface(const NetworkInfo& networkInfo, InterfaceEntry *ie);
};

#endif

