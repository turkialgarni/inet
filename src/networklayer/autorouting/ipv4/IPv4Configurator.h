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

#ifndef __INET_IPV4CONFIGURATOR_H
#define __INET_IPV4CONFIGURATOR_H

#include <omnetpp.h>
#include "Topology.h"
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
class INET_API IPv4Configurator : public cSimpleModule
{
  public:
    class NodeInfo;

    class LinkInfo;

    class InterfaceInfo : public cObject {
        public:
            NodeInfo *nodeInfo;
            LinkInfo *linkInfo;
            InterfaceEntry *interfaceEntry;
            bool configure;  //TODO code should obey it!
            IPv4Address address;
            uint32 addressSpecifiedBits;
            IPv4Address netmask;
            uint32 netmaskSpecifiedBits;

            InterfaceInfo(NodeInfo *nodeInfo, LinkInfo *linkInfo, InterfaceEntry *interfaceEntry) {
                this->nodeInfo = nodeInfo;
                this->linkInfo = linkInfo;
                this->interfaceEntry = interfaceEntry;
                configure = true;
                // NOTE: default IP addresses are in the subnet 10.x.x.x/255.255.x.x
                address = IPv4Address(0x0A000000);
                addressSpecifiedBits = 0xFF000000;
                netmask = IPv4Address(0xFFFF0000);
                netmaskSpecifiedBits = 0xFFFF0000;
            }
            virtual std::string getFullPath() const { return interfaceEntry->getFullPath(); }
    };

    class NodeInfo : public cObject {
        public:
            bool isIPNode;
            cModule *module;
            IInterfaceTable *interfaceTable;
            IRoutingTable *routingTable;
            std::vector<InterfaceInfo*> interfaceInfos;

            NodeInfo(cModule *module) { this->module = module; isIPNode = false; interfaceTable = NULL; routingTable = NULL; }
            virtual std::string getFullPath() const { return module->getFullPath(); }
    };

    class LinkInfo : public cObject {
        public:
            std::vector<InterfaceInfo*> interfaceInfos; // interfaces on that LAN or point-to-point link
            InterfaceInfo* gatewayInterfaceInfo; // non NULL if all hosts have 1 non-loopback interface except one host that has two of them

            LinkInfo() { gatewayInterfaceInfo = NULL; }
            ~LinkInfo() { for (int i = 0; i < interfaceInfos.size(); i++) delete interfaceInfos[i]; }
    };

    class NetworkInfo : public cObject {  //TODO put Topology* into it
        public:
            std::vector<LinkInfo*> linkInfos;

            ~NetworkInfo() { for (int i = 0; i < linkInfos.size(); i++) delete linkInfos[i]; }
    };

    class RouteInfo {
        public:
            int color;
            bool enabled;
            uint32 destination;
            uint32 netmask;
            std::vector<RouteInfo *> originalRouteInfos; // routes that are routed by this one from the unoptimized routing table

            RouteInfo(int color, uint32 destination, uint32 netmask) { this->color = color; this->enabled = true; this->destination = destination; this->netmask = netmask; }
    };

    class RoutingTableInfo {
        public:
            std::vector<RouteInfo *> routeInfos;

            int addRouteInfo(RouteInfo *routeInfo) {
                std::vector<RouteInfo *>::iterator it = upper_bound(routeInfos.begin(), routeInfos.end(), routeInfo, routeInfoLessThan);
                int index = it - routeInfos.begin();
                routeInfos.insert(it, routeInfo);
                return index;
            }
            void removeRouteInfo(const RouteInfo *routeInfo) { routeInfos.erase(std::find(routeInfos.begin(), routeInfos.end(), routeInfo)); }
            RouteInfo *findBestMatchingRouteInfo(const uint32 destination) const { return findBestMatchingRouteInfo(destination, 0, routeInfos.size()); }
            RouteInfo *findBestMatchingRouteInfo(const uint32 destination, int begin, int end) const {
                for (int index = begin; index < end; index++) {
                    RouteInfo *routeInfo = routeInfos.at(index);
                    if (routeInfo->enabled && !((destination ^ routeInfo->destination) & routeInfo->netmask))
                        return const_cast<RouteInfo *>(routeInfo);
                }
                return NULL;
            }
            static bool routeInfoLessThan(const RouteInfo *a, const RouteInfo *b) { return a->netmask != b->netmask ? a->netmask > b->netmask : a->destination < b->destination; }
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
            bool matchesAny() { return matchesany; }
    };

  protected:
    virtual int numInitStages() const  { return 3; }
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *msg);

    // main functionality
    virtual void extractTopology(Topology& topology, NetworkInfo& networkInfo);
    virtual void readAddressConfiguration(cXMLElement *root, Topology& topology, NetworkInfo& networkInfo);
    virtual void assignAddresses(Topology& topology, NetworkInfo& networkInfo);
    virtual void addManualRoutes(cXMLElement *root, Topology& topology, NetworkInfo& networkInfo);
    virtual void addStaticRoutes(Topology& topology, NetworkInfo& networkInfo);
    virtual void optimizeRoutes(std::vector<IPv4Route *> *routes);
    virtual void dumpTopology(Topology& topology);
    virtual void dumpAddresses(NetworkInfo& networkInfo);
    virtual void dumpRoutes(Topology& topology);
    virtual void dumpConfig(Topology& topology, NetworkInfo& networkInfo);

    // helper functions
    virtual void parseAddressAndSpecifiedBits(const char *addressAttr, uint32_t& outAddress, uint32_t& outAddressSpecifiedBits);
    virtual bool linkContainsMatchingHostExcept(LinkInfo *linkInfo, Matcher *hostMatcher, cModule *exceptModule);
    virtual void visitNeighbor(Topology::LinkOut *linkOut, LinkInfo* linkInfo, std::set<InterfaceEntry*>& interfacesSeen, std::vector<Topology::Node*>& nodesVisited);
    const char *getMandatoryAttribute(cXMLElement *element, const char *attr);
    virtual void resolveInterfaceAndGateway(NodeInfo *node, const char *interfaceAttr, const char *gatewayAttr,
            InterfaceEntry *&outIE, IPv4Address& outGateway, const NetworkInfo& networkInfo);
    InterfaceInfo *findInterfaceOnLinkByNode(LinkInfo *linkInfo, cModule *node);
    InterfaceInfo *findInterfaceOnLinkByNodeAddress(LinkInfo *linkInfo, IPv4Address address);
    LinkInfo *findLinkOfInterface(const NetworkInfo& networkInfo, InterfaceEntry *interfaceEntry);
    InterfaceInfo *createInterfaceInfo(NodeInfo *nodeInfo, LinkInfo *linkInfo, InterfaceEntry *interfaceEntry);
};

#endif
