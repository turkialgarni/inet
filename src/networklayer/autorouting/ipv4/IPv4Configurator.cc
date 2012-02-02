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
#include "stlutils.h"
#include "IRoutingTable.h"
#include "IInterfaceTable.h"
#include "IPvXAddressResolver.h"
#include "IPv4Configurator.h"
#include "InterfaceEntry.h"
#include "IPv4InterfaceData.h"
#include "PatternMatcher.h"


Define_Module(IPv4Configurator);

inline bool isEmpty(const char *s) {return !s || !s[0];}
inline bool isNotEmpty(const char *s) {return s && s[0];}

// compile time macros to disable or enable logging
#define EV_ENABLED EV
#define EV_DISABLED true?ev:ev

// compile time log levels
#define EV_DEBUG EV_DISABLED
#define EV_INFO EV_ENABLED

void static printTimeSpentUsingDuration(const char *name, long duration)
{
    EV_INFO << "Time spent in " << name << ": " << ((double)duration / CLOCKS_PER_SEC) << "s" << endl;
}

void static printTimeSpentUsingBegin(const char *name, long begin)
{
    printTimeSpentUsingDuration(name, clock() - begin);
}

void IPv4Configurator::initialize(int stage)
{
    if (stage==2) //TODO parameter: melyik stage-ben csinal a cimkonfiguralast, es melyikben a route-okat
    {
        long initializeBegin = clock();
        long begin = initializeBegin;
        Topology topology("topology");
        NetworkInfo networkInfo;

        // extract topology into the Topology object, then fill in a LinkInfo[] vector
        begin = clock();
        extractTopology(topology, networkInfo);
        printTimeSpentUsingBegin("extractTopology", begin);

        // read the configuration from XML; it will serve as input for address assignment
        begin = clock();
        readAddressConfiguration(par("config").xmlValue(), topology, networkInfo);
        printTimeSpentUsingBegin("readAddressConfiguration", begin);

        // assign addresses to IPv4 nodes
        begin = clock();
        assignAddresses(topology, networkInfo);
        printTimeSpentUsingBegin("assignAddresses", begin);

        // read and configure manual routes from the XML configuration
        begin = clock();
        addManualRoutes(par("config").xmlValue(), topology, networkInfo); // TODO use 2 separate XML files? "interfaceConfig", "manualRoutes" parameters
        printTimeSpentUsingBegin("addManualRoutes", begin);

        // calculate shortest paths, and add corresponding static routes
        if (par("addStaticRoutes").boolValue()) {
            begin = clock();
            addStaticRoutes(topology, networkInfo);
            printTimeSpentUsingBegin("addStaticRoutes", begin);
        }

        // dump the result if requested
        if (par("dumpTopology").boolValue()) {
            begin = clock();
            dumpTopology(topology);
            printTimeSpentUsingBegin("dumpTopology", begin);
        }
        if (par("dumpAddresses").boolValue()) {
            begin = clock();
            dumpAddresses(networkInfo);
            printTimeSpentUsingBegin("dumpAddresses", begin);
        }
        if (par("dumpRoutes").boolValue()) {
            begin = clock();
            dumpRoutes(topology);
            printTimeSpentUsingBegin("dumpRoutes", begin);
        }
        if (strcmp(par("dumpConfig"), "")) {
            begin = clock();
            dumpConfig(topology, networkInfo);
            printTimeSpentUsingBegin("dumpConfig", begin);
        }

        printTimeSpentUsingBegin("IPv4Configurator initialize", initializeBegin);
    }
}

static Topology::LinkOut *findLinkOut(Topology::Node *node, int gateId)
{
    for (int i=0; i<node->getNumOutLinks(); i++)
        if (node->getLinkOut(i)->getLocalGateId() == gateId)
            return node->getLinkOut(i);
    return NULL;
}

void IPv4Configurator::extractTopology(Topology& topology, NetworkInfo& networkInfo)
 {
    // extract topology
    topology.extractByProperty("node");
    EV_DEBUG << "Topology found " << topology.getNumNodes() << " nodes\n";

    // extract nodes, fill in isIPNode, interfaceTable and routingTable members in nodeInfo[]
    for (int i = 0; i < topology.getNumNodes(); i++) {
        Topology::Node *node = topology.getNode(i);
        cModule *module = node->getModule();
        NodeInfo *nodeInfo = new NodeInfo(module);
        node->setPayload(nodeInfo);
        nodeInfo->module = module;
        nodeInfo->interfaceTable = IPvXAddressResolver().findInterfaceTableOf(module);
        nodeInfo->isIPNode = nodeInfo->interfaceTable != NULL;
        if (nodeInfo->isIPNode) {
            nodeInfo->routingTable = IPvXAddressResolver().routingTableOf(module);
            if (!nodeInfo->routingTable->isIPForwardingEnabled())
                node->setWeight(DBL_MAX);
        }
    }

    // extract links and interfaces
    std::set<InterfaceEntry*> interfacesSeen;
    for (int i = 0; i < topology.getNumNodes(); i++) {
        Topology::Node *node = topology.getNode(i);
        NodeInfo *nodeInfo = (NodeInfo *)node->getPayload();
        cModule *module = node->getModule();
        IInterfaceTable *interfaceTable = IPvXAddressResolver().findInterfaceTableOf(module);
        if (interfaceTable) {
            for (int j = 0; j < interfaceTable->getNumInterfaces(); j++) {
                InterfaceEntry *interfaceEntry = interfaceTable->getInterface(j);
                if (!interfaceEntry->isLoopback() && interfacesSeen.count(interfaceEntry) == 0) {
                    // store interface as belonging to a new network link
                    LinkInfo *linkInfo = new LinkInfo();
                    networkInfo.linkInfos.push_back(linkInfo);
                    linkInfo->interfaceInfos.push_back(createInterfaceInfo(nodeInfo, linkInfo, interfaceEntry));
                    interfacesSeen.insert(interfaceEntry);

                    // visit neighbor (and potentially the whole LAN, recursively)
                    Topology::LinkOut *linkOut = findLinkOut(topology.getNode(i), interfaceEntry->getNodeOutputGateId());
                    if (linkOut) {
                        std::vector<Topology::Node*> empty;
                        visitNeighbor(linkOut, linkInfo, interfacesSeen, empty);
                    }

                    // determine gatewayInterfaceInfo
                    for (int k = 0; k < linkInfo->interfaceInfos.size(); k++) {
                        InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[k];
                        IInterfaceTable *interfaceTable = interfaceInfo->nodeInfo->interfaceTable;
                        // count non-loopback source interfaces
                        int nonLoopbackInterfaceCount = 0;
                        for (int l = 0; l < interfaceTable->getNumInterfaces(); l++)
                            if (!interfaceTable->getInterface(l)->isLoopback())
                                nonLoopbackInterfaceCount++;
                        // check for having a single gateway interface
                        if (nonLoopbackInterfaceCount > 1) {
                            if (linkInfo->gatewayInterfaceInfo) {
                                linkInfo->gatewayInterfaceInfo = NULL;
                                break;
                            }
                            else
                                linkInfo->gatewayInterfaceInfo = interfaceInfo;
                        }
                    }
                }
            }
        }
    }
}

void IPv4Configurator::visitNeighbor(Topology::LinkOut *linkOut, LinkInfo* linkInfo, std::set<InterfaceEntry*>& interfacesSeen, std::vector<Topology::Node*>& deviceNodesVisited)
{
    Topology::Node *neighborNode = linkOut->getRemoteNode();
    cModule *neighborModule = neighborNode->getModule();
    NodeInfo *neighborNodeInfo = (NodeInfo *)neighborNode->getPayload();
    int neighborInputGateId = linkOut->getRemoteGateId();
    IInterfaceTable *neighborInterfaceTable = IPvXAddressResolver().findInterfaceTableOf(neighborModule);
    if (neighborInterfaceTable) {
        // neighbor is a host or router, just add the interface
        InterfaceEntry *neighborInterfaceEntry = neighborInterfaceTable->getInterfaceByNodeInputGateId(neighborInputGateId);
        if (interfacesSeen.count(neighborInterfaceEntry) == 0) {
            linkInfo->interfaceInfos.push_back(createInterfaceInfo(neighborNodeInfo, linkInfo, neighborInterfaceEntry));
            interfacesSeen.insert(neighborInterfaceEntry);
        }
    }
    else {
        // assume that neighbor is an L2 or L1 device (bus/hub/switch/bridge/access point/etc); visit all its output links
        Topology::Node *deviceNode = linkOut->getRemoteNode();
        if (!contains(deviceNodesVisited, deviceNode)) {
            deviceNodesVisited.push_back(deviceNode);
            for (int i = 0; i < deviceNode->getNumOutLinks(); i++) {
                Topology::LinkOut *deviceLinkOut = deviceNode->getLinkOut(i);
                visitNeighbor(deviceLinkOut, linkInfo, interfacesSeen, deviceNodesVisited);
            }
        }
    }
}

IPv4Configurator::InterfaceInfo *IPv4Configurator::createInterfaceInfo(NodeInfo *nodeInfo, LinkInfo* linkInfo, InterfaceEntry *interfaceEntry)
{
    InterfaceInfo *interfaceInfo = new InterfaceInfo(nodeInfo, linkInfo, interfaceEntry);
    IPv4InterfaceData *interfaceData = interfaceEntry->ipv4Data();
    IPv4Address address = interfaceData->getIPAddress();
    IPv4Address netmask = interfaceData->getNetmask();
    bool addressUnspecified = address.isUnspecified();
    if (!addressUnspecified) {
        interfaceInfo->address = address;
        interfaceInfo->netmask = netmask;
        interfaceInfo->addressSpecifiedBits = 0xFFFFFFFF;
        interfaceInfo->netmaskSpecifiedBits = 0xFFFFFFFF;
    }
    interfaceInfo->configure = addressUnspecified;
    nodeInfo->interfaceInfos.push_back(interfaceInfo);
    return interfaceInfo;
}

IPv4Configurator::Matcher::Matcher(const char *pattern)
{
    matchesany = isEmpty(pattern);
    if (matchesany)
        return;
    cStringTokenizer tokenizer(pattern);
    while (tokenizer.hasMoreTokens())
        matchers.push_back(new inet::PatternMatcher(tokenizer.nextToken(), true, true, true));
}

IPv4Configurator::Matcher::~Matcher()
{
    for (int i=0; i<matchers.size(); i++)
        delete matchers[i];
}

bool IPv4Configurator::Matcher::matches(const char *s)
{
    if (matchesany)
        return true;
    for (int i=0; i<matchers.size(); i++)
        if (matchers[i]->matches(s))
            return true;
    return false;
}

inline bool strToBool(const char *str, bool defaultValue)
{
    if (!str || !str[0])
        return defaultValue;
    if (strcmp(str,"true")==0)
        return true;
    if (strcmp(str,"false")==0)
        return false;
    throw cRuntimeError("invalid boolean XML attribute:'%s'", str);
}

void IPv4Configurator::readAddressConfiguration(cXMLElement *root, Topology& topology, NetworkInfo& networkInfo)
{
    std::set<InterfaceInfo*> interfacesSeen;
    cXMLElementList interfaceElements = root->getChildrenByTagName("interface");

    // If there is no XML configuration, all interfaces are configured with some default address range
    // (see InterfaceInfo ctor); however, if there is at least one <interface> element, then there is
    // no such default, all interfaces to be configured should be covered with <interface> elements.
    if (interfaceElements.size() > 0)
    {
        // set configure=false for on all interfaces
        for (int i = 0; i < networkInfo.linkInfos.size(); i++)
        {
            LinkInfo *linkInfo = networkInfo.linkInfos[i];
            for (int j = 0; j < linkInfo->interfaceInfos.size(); j++)
            {
                InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[j];
                interfaceInfo->configure = false;
            }
        }
    }
    for (int i = 0; i < interfaceElements.size(); i++)
    {
        cXMLElement *interfaceElement = interfaceElements[i];
        const char *hostAttr = interfaceElement->getAttribute("hosts");  // "host* router[0..3]"
        const char *interfaceAttr = interfaceElement->getAttribute("names"); // i.e. interface names, like "eth* ppp0"
        const char *towardsAttr = interfaceElement->getAttribute("towards"); // neighbor host names, like "ap switch"
        const char *addressAttr = interfaceElement->getAttribute("address"); // "10.0.x.x"
        const char *netmaskAttr = interfaceElement->getAttribute("netmask"); // "255.255.x.x"
        const char *multicastGroupsAttr = interfaceElement->getAttribute("multicastgroups"); // "224.0.0.1 224.0.1.33"
        const char *mtuAttr = interfaceElement->getAttribute("mtu"); // integer

        try
        {
            // parse host/interface/towards expressions
            Matcher hostMatcher(hostAttr);
            Matcher interfaceMatcher(interfaceAttr);
            Matcher towardsMatcher(towardsAttr);

            // parse address/netmask constraints
            bool haveAddressConstraint = isNotEmpty(addressAttr);
            bool haveNetmaskConstraint = isNotEmpty(netmaskAttr);

            uint32_t address, addressSpecifiedBits, netmask, netmaskSpecifiedBits;
            if (haveAddressConstraint)
                parseAddressAndSpecifiedBits(addressAttr, address, addressSpecifiedBits);
            if (haveNetmaskConstraint)
                parseAddressAndSpecifiedBits(netmaskAttr, netmask, netmaskSpecifiedBits);

            std::vector<IPv4Address> multicastGroups;
            cStringTokenizer tokenizer(multicastGroupsAttr);
            while (tokenizer.hasMoreTokens()) {
                IPv4Address addr = IPv4Address(tokenizer.nextToken());
                if (!addr.isMulticast())
                    throw cRuntimeError("non-multicast address %s found in the multicastgroups attribute", addr.str().c_str());
                multicastGroups.push_back(addr);
            }

            // configure address/netmask constraints on matching interfaces
            for (int i = 0; i < networkInfo.linkInfos.size(); i++)
            {
                LinkInfo *linkInfo = networkInfo.linkInfos[i];
                for (int j = 0; j < linkInfo->interfaceInfos.size(); j++)
                {
                    InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[j];
                    if (interfacesSeen.count(interfaceInfo) == 0)
                    {
                        cModule *hostModule = interfaceInfo->interfaceEntry->getInterfaceTable()->getHostModule();
                        std::string hostFullPath = hostModule->getFullPath();
                        std::string hostShortenedFullPath = hostFullPath.substr(hostFullPath.find('.')+1);

                        // Note: "hosts", "interfaces" and "towards" must ALL match on the interface for the rule to apply
                        if ((hostMatcher.matchesAny() || hostMatcher.matches(hostShortenedFullPath.c_str()) || hostMatcher.matches(hostFullPath.c_str())) &&
                            (interfaceMatcher.matchesAny() || interfaceMatcher.matches(interfaceInfo->interfaceEntry->getFullName())) &&
                            (towardsMatcher.matchesAny() || linkContainsMatchingHostExcept(linkInfo, &towardsMatcher, hostModule)))
                        {
                            // unicast address constraints
                            interfaceInfo->configure = haveAddressConstraint;
                            if (interfaceInfo->configure) {
                                interfaceInfo->address = address;
                                interfaceInfo->addressSpecifiedBits = addressSpecifiedBits;
                                if (haveNetmaskConstraint) {
                                    interfaceInfo->netmask = netmask;
                                    interfaceInfo->netmaskSpecifiedBits = netmaskSpecifiedBits;
                                }
                            }
                            // multicast addresses (note: even if configure==false! multicast addresses are treated differently)
                            for (int k = 0; k < multicastGroups.size(); k++)
                                interfaceInfo->interfaceEntry->ipv4Data()->joinMulticastGroup(multicastGroups[k]);

                            // mtu
                            if (isNotEmpty(mtuAttr))
                                interfaceInfo->interfaceEntry->setMtu(atoi(mtuAttr));

                            interfacesSeen.insert(interfaceInfo);
                            EV_DEBUG << hostModule->getFullPath() << ":" << interfaceInfo->interfaceEntry->getFullName() << endl;
                        }
                    }
                }
            }
        }
        catch (std::exception& e)
        {
            throw cRuntimeError("Error in XML <interface> element at %s: %s", interfaceElement->getSourceLocation(), e.what());
        }
    }
}

void IPv4Configurator::parseAddressAndSpecifiedBits(const char *addressAttr, uint32_t& outAddress, uint32_t& outAddressSpecifiedBits)
{
    // change "10.0.x.x" to "10.0.0.0" (for address) and "255.255.0.0" (for specifiedBits)
    std::string address;
    std::string specifiedBits;
    cStringTokenizer tokenizer(addressAttr, ".");
    while (tokenizer.hasMoreTokens())
    {
        std::string token = tokenizer.nextToken();
        address += (token == "x") ? "0." : (token+".");
        specifiedBits += (token == "x") ? "0." : "255.";
    }
    address = address.substr(0, address.size()-1);
    specifiedBits = specifiedBits.substr(0, specifiedBits.size()-1);

    if (!IPv4Address::isWellFormed(address.c_str()) || !IPv4Address::isWellFormed(specifiedBits.c_str()))
        throw cRuntimeError("Malformed IPv4 address or netmask constraint '%s'", addressAttr);

    outAddress = IPv4Address(address.c_str()).getInt();
    outAddressSpecifiedBits = IPv4Address(specifiedBits.c_str()).getInt();
}

bool IPv4Configurator::linkContainsMatchingHostExcept(LinkInfo *linkInfo, Matcher *hostMatcher, cModule *exceptModule)
{
    for (int i = 0; i < linkInfo->interfaceInfos.size(); i++)
    {
        InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[i];
        cModule *hostModule = interfaceInfo->interfaceEntry->getInterfaceTable()->getHostModule();
        if (hostModule == exceptModule)
            continue;
        std::string hostFullPath = hostModule->getFullPath();
        std::string hostShortenedFullPath = hostFullPath.substr(hostFullPath.find('.')+1);
        if (hostMatcher->matches(hostShortenedFullPath.c_str()) || hostMatcher->matches(hostFullPath.c_str()))
            return true;
    }
    return false;
}

void IPv4Configurator::handleMessage(cMessage *msg)
{
    throw cRuntimeError("this module doesn't handle messages, it runs only in initialize()");
}

void IPv4Configurator::dumpTopology(Topology& topology)
{
    for (int i = 0; i < topology.getNumNodes(); i++) {
        Topology::Node *node = topology.getNode(i);
        EV_INFO << "Node " << node->getPayload()->getFullPath() << endl;
        for (int j = 0; j < node->getNumOutLinks(); j++) {
            Topology::LinkOut *linkOut = node->getLinkOut(j);
            ASSERT(linkOut->getLocalNode() == node);
            EV_INFO << "     -> " << linkOut->getRemoteNode()->getPayload()->getFullPath() << " " << linkOut->getWeight() << endl;
        }
        for (int j = 0; j < node->getNumInLinks(); j++) {
            Topology::LinkIn *linkIn = node->getLinkIn(j);
            ASSERT(linkIn->getLocalNode() == node);
            EV_INFO << "     <- " << linkIn->getRemoteNode()->getPayload()->getFullPath() << " " << linkIn->getWeight() << endl;
        }
    }
}

void IPv4Configurator::dumpAddresses(NetworkInfo& networkInfo)
{
    for (int i = 0; i < networkInfo.linkInfos.size(); i++) {
        EV_INFO << "Link " << i << endl;
        LinkInfo* linkInfo = networkInfo.linkInfos[i];
        for (int j = 0; j < linkInfo->interfaceInfos.size(); j++) {
            InterfaceEntry *interfaceEntry = linkInfo->interfaceInfos[j]->interfaceEntry;
            cModule *host = dynamic_cast<cModule *>(interfaceEntry->getInterfaceTable())->getParentModule();
            EV_INFO << "    " << host->getFullName() << " / " << interfaceEntry->getName() << " " << interfaceEntry->info() << endl;
        }
    }
}

void IPv4Configurator::dumpRoutes(Topology& topology)
{
    for (int i = 0; i < topology.getNumNodes(); i++) {
        Topology::Node *node = topology.getNode(i);
        NodeInfo *nodeInfo = (NodeInfo *)node->getPayload();
        if (nodeInfo->isIPNode && nodeInfo->routingTable) {
            EV_INFO << "Node " << nodeInfo->module->getFullPath() << endl;
            nodeInfo->routingTable->printRoutingTable();
        }
    }
}

void IPv4Configurator::dumpConfig(Topology& topology, NetworkInfo& networkInfo)
{
    FILE *f;
    f = fopen(par("dumpConfig").stringValue(), "w");
    if (!f)
        throw cRuntimeError("Cannot configurator output file");
    fprintf(f, "<config>\n");
    // interfaces
    for (int i = 0; i < networkInfo.linkInfos.size(); i++) {
        EV_INFO << "Link " << i << endl;
        LinkInfo* linkInfo = networkInfo.linkInfos[i];
        for (int j = 0; j < linkInfo->interfaceInfos.size(); j++) {
            InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[j];
            InterfaceEntry *interfaceEntry = interfaceInfo->interfaceEntry;
            IPv4InterfaceData *interfaceData = interfaceEntry->ipv4Data();
            std::stringstream stream;
            stream << "   <interface hosts=\"" << interfaceInfo->nodeInfo->module->getFullPath() << "\" names=\"" << interfaceEntry->getName() <<
                      "\" address=\"" << interfaceData->getIPAddress() << "\" netmask=\"" << interfaceData->getNetmask() << "\"/>" << endl;
            fprintf(f, stream.str().c_str());
        }
    }
    // routes
    for (int i = 0; i < topology.getNumNodes(); i++) {
        Topology::Node *node = topology.getNode(i);
        NodeInfo *nodeInfo = (NodeInfo *)node->getPayload();
        if (nodeInfo->isIPNode && nodeInfo->routingTable) {
            IRoutingTable *routingTable = nodeInfo->routingTable;
            for (int j = 0; j < routingTable->getNumRoutes(); j++) {
                IPv4Route *route = routingTable->getRoute(j);
                std::stringstream stream;
                IPv4Address netmask = route->getNetmask();
                IPv4Address gateway = route->getGateway();
                stream << "   <route host=\"" << nodeInfo->module->getFullPath();
                stream << "\" destination=\""; if (route->getDestination().isUnspecified()) stream << "*"; else stream << route->getDestination();
                stream << "\" netmask=\""; if (route->getNetmask().isUnspecified()) stream << "*"; else stream << route->getNetmask();
                stream << "\" gateway=\""; if (route->getGateway().isUnspecified()) stream << "*"; else stream << route->getGateway();
                stream << "\" interface=\"" << route->getInterfaceName() << "\" metric=\"" << route->getMetric() << "\"/>" << endl;
                fprintf(f, stream.str().c_str());
            }
        }
    }
    fprintf(f, "</config>");
    fflush(f);
    fclose(f);
}

// how many bits are needed to represent count different values
inline int getRepresentationBitCount(uint32 count)
{
    int bitCount = 0;
    while ((1<<bitCount) < count)
        bitCount++;
    return bitCount;
}

// 0 means the most significant bit
static int getMostSignificantBitIndex(uint32 value, uint32 bitValue, int defaultIndex)
{
    int bitIndex = 0;
    for (int bitIndex = 31; bitIndex >= 0; bitIndex--) {
        uint32 mask = 1 << bitIndex;
        if ((value & mask) == (bitValue << bitIndex))
            return bitIndex;
    }
    return defaultIndex;
}

// 0 means the most significant bit
static int getLeastSignificantBitIndex(uint32 value, uint32 bitValue, int defaultIndex)
{
    int bitIndex = 0;
    for (int bitIndex = 0; bitIndex < 32; bitIndex++) {
        uint32 mask = 1 << bitIndex;
        if ((value & mask) == (bitValue << bitIndex))
            return bitIndex;
    }
    return defaultIndex;
}

// get packed bits from value specified by mask
static uint32 getPackedBits(uint32 value, uint32 valueMask)
{
    uint32 packedValue = 0;
    int packedValueIndex = 0;
    for (int valueIndex = 0; valueIndex < 32; valueIndex++) {
        uint32 valueBitMask = 1 << valueIndex;
        if ((valueMask & valueBitMask) != 0) {
            if ((value & valueBitMask) != 0)
                packedValue |= 1 << packedValueIndex;
            packedValueIndex++;
        }
    }
    return packedValue;
}

// set packed bits in value specified by mask
static uint32 setPackedBits(uint32 value, uint32 valueMask, uint32 packedValue)
{
    int packedValueIndex = 0;
    for (int valueIndex = 0; valueIndex < 32; valueIndex++) {
        uint32 valueBitMask = 1 << valueIndex;
        if ((valueMask & valueBitMask) != 0) {
            uint32 newValueBitMask = 1 << packedValueIndex;
            if ((packedValue & newValueBitMask) != 0)
                value |= valueBitMask;
            else
                value &= ~valueBitMask;
            packedValueIndex++;
        }
    }
    return value;
}

void IPv4Configurator::assignAddresses(Topology& topology, NetworkInfo& networkInfo)
{
    std::vector<IPv4Address> assignedNetworkAddresses;
    std::vector<IPv4Address> assignedNetworkNetmasks;
    std::vector<IPv4Address> assignedInterfaceAddresses;
    std::map<IPv4Address, InterfaceEntry *> assignedAddressToInterfaceEntryMap;
    // iterate through all links and process them separately one by one
    for (int linkIndex = 0; linkIndex < networkInfo.linkInfos.size(); linkIndex++) {
        LinkInfo *selectedLink = networkInfo.linkInfos[linkIndex];
        // repeat until all interfaces of the selected link become configured
        // and assign addresses to groups of interfaces having compatible address and netmask specifications
        std::vector<InterfaceInfo*> unconfiguredInterfaces = selectedLink->interfaceInfos;
        while (unconfiguredInterfaces.size() != 0) {

            // STEP 1.
            // find a subset of the unconfigured interfaces that have compatible address and netmask specifications
            // determine the merged address and netmask specifications according to the following table
            // the '?' symbol means the bit is unspecified, the 'X' symbol means the bit is incompatible
            // | * | 0 | 1 | ? |
            // | 0 | 0 | X | 0 |
            // | 1 | X | 1 | 1 |
            // | ? | 0 | 1 | ? |
            // the result of step 1 is the following:
            uint32 mergedAddress = 0;                 // compatible bits of the merged address (both 0 and 1 are address bits)
            uint32 mergedAddressSpecifiedBits = 0;    // mask for the valid compatible bits of the merged address (0 means unspecified, 1 means specified)
            uint32 mergedAddressIncompatibleBits = 0; // incompatible bits of the merged address (0 means compatible, 1 means incompatible)
            uint32 mergedNetmask = 0;                 // compatible bits of the merged netmask (both 0 and 1 are netmask bits)
            uint32 mergedNetmaskSpecifiedBits = 0;    // mask for the compatible bits of the merged netmask (0 means unspecified, 1 means specified)
            uint32 mergedNetmaskIncompatibleBits = 0; // incompatible bits of the merged netmask (0 means compatible, 1 means incompatible)
            std::vector<InterfaceInfo*> compatibleInterfaces; // the list of compatible interfaces
            for (int unconfiguredInterfaceIndex = 0; unconfiguredInterfaceIndex < unconfiguredInterfaces.size(); unconfiguredInterfaceIndex++) {
                InterfaceInfo *candidateInterface = unconfiguredInterfaces[unconfiguredInterfaceIndex];
                InterfaceEntry *interfaceEntry = candidateInterface->interfaceEntry;
                // extract candidate interface configuration data
                uint32 candidateAddress = candidateInterface->address.getInt();
                uint32 candidateAddressSpecifiedBits = candidateInterface->addressSpecifiedBits;
                uint32 candidateNetmask = candidateInterface->netmask.getInt();
                uint32 candidateNetmaskSpecifiedBits = candidateInterface->netmaskSpecifiedBits;
                EV_DEBUG << "Trying to merge " << interfaceEntry->getFullPath() << " interface with address specification: " << IPv4Address(candidateAddress) << " / " << IPv4Address(candidateAddressSpecifiedBits) << endl;
                EV_DEBUG << "Trying to merge " << interfaceEntry->getFullPath() << " interface with netmask specification: " << IPv4Address(candidateNetmask) << " / " << IPv4Address(candidateNetmaskSpecifiedBits) << endl;
                // determine merged netmask bits
                uint32 commonNetmaskSpecifiedBits = mergedNetmaskSpecifiedBits & candidateNetmaskSpecifiedBits;
                uint32 newMergedNetmask = mergedNetmask | (candidateNetmask & candidateNetmaskSpecifiedBits);
                uint32 newMergedNetmaskSpecifiedBits = mergedNetmaskSpecifiedBits | candidateNetmaskSpecifiedBits;
                uint32 newMergedNetmaskIncompatibleBits = mergedNetmaskIncompatibleBits | ((mergedNetmask & commonNetmaskSpecifiedBits) ^ (candidateNetmask & commonNetmaskSpecifiedBits));
                // skip interface if there's a bit where the netmasks are incompatible
                if (newMergedNetmaskIncompatibleBits != 0)
                    continue;
                // determine merged address bits
                uint32 commonAddressSpecifiedBits = mergedAddressSpecifiedBits & candidateAddressSpecifiedBits;
                uint32 newMergedAddress = mergedAddress | (candidateAddress & candidateAddressSpecifiedBits);
                uint32 newMergedAddressSpecifiedBits = mergedAddressSpecifiedBits | candidateAddressSpecifiedBits;
                uint32 newMergedAddressIncompatibleBits = mergedAddressIncompatibleBits | ((mergedAddress & commonAddressSpecifiedBits) ^ (candidateAddress & commonAddressSpecifiedBits));
                // skip interface if there's a bit where the netmask is 1 and the addresses are incompatible
                if ((newMergedNetmask & newMergedNetmaskSpecifiedBits & newMergedAddressIncompatibleBits) != 0)
                    continue;
                // store merged address bits
                mergedAddress = newMergedAddress;
                mergedAddressSpecifiedBits = newMergedAddressSpecifiedBits;
                mergedAddressIncompatibleBits = newMergedAddressIncompatibleBits;
                // store merged netmask bits
                mergedNetmask = newMergedNetmask;
                mergedNetmaskSpecifiedBits = newMergedNetmaskSpecifiedBits;
                mergedNetmaskIncompatibleBits = newMergedNetmaskIncompatibleBits;
                // add interface to the list of compatible interfaces
                compatibleInterfaces.push_back(candidateInterface);
                EV_DEBUG << "Merged address specification: " << IPv4Address(mergedAddress) << " / " << IPv4Address(mergedAddressSpecifiedBits) << " / " << IPv4Address(mergedAddressIncompatibleBits) << endl;
                EV_DEBUG << "Merged netmask specification: " << IPv4Address(mergedNetmask) << " / " << IPv4Address(mergedNetmaskSpecifiedBits) << " / " << IPv4Address(mergedNetmaskIncompatibleBits) << endl;
            }
            EV_DEBUG << "Found " << compatibleInterfaces.size() << " compatible interfaces" << endl;

            // STEP 2.
            // determine the valid range of netmask length by searching from left to right the last 1 and the first 0 bits
            // also consider the incompatible bits of the address to limit the range of valid netmasks accordingly
            int minimumNetmaskLength = 32 - getLeastSignificantBitIndex(mergedNetmask & mergedNetmaskSpecifiedBits, 1, 32); // 0 means 0.0.0.0, 32 means 255.255.255.255
            int maximumNetmaskLength = 31 - getMostSignificantBitIndex(~mergedNetmask & mergedNetmaskSpecifiedBits, 1, -1); // 0 means 0.0.0.0, 32 means 255.255.255.255
            maximumNetmaskLength = std::min(maximumNetmaskLength, 31 - getMostSignificantBitIndex(mergedAddressIncompatibleBits, 1, -1));
            // make sure there are enough bits to configure a unique address for all interface
            // the +2 means that all-0 and all-1 addresses are ruled out
            int compatibleInterfaceCount = compatibleInterfaces.size() + 2;
            int interfaceAddressBitCount = getRepresentationBitCount(compatibleInterfaceCount);
            maximumNetmaskLength = std::min(maximumNetmaskLength, 32 - interfaceAddressBitCount);
            EV_DEBUG << "Netmask valid length range: " << minimumNetmaskLength << " - " << maximumNetmaskLength << endl;

            // STEP 3.
            // determine network address and network netmask by iterating through valid netmasks from longest to shortest
            int netmaskLength = -1;
            uint32 networkAddress = 0; // network part of the addresses  (e.g. 10.1.1.0)
            uint32 networkNetmask = 0; // netmask for the network (e.g. 255.255.255.0)
            for (netmaskLength = maximumNetmaskLength; netmaskLength >= minimumNetmaskLength; netmaskLength--) {
                networkNetmask = ((1 << netmaskLength) - 1) << (32 - netmaskLength);
                EV_DEBUG << "Trying network netmask: " << IPv4Address(networkNetmask) << " : " << netmaskLength << endl;
                networkAddress = mergedAddress & mergedAddressSpecifiedBits & networkNetmask;
                uint32 networkAddressUnspecifiedBits = ~mergedAddressSpecifiedBits & networkNetmask; // 1 means the network address unspecified
                uint32 networkAddressUnspecifiedPartMaximum = 0;
                for (int i = 0; i < assignedNetworkAddresses.size(); i++) {
                    uint32 assignedNetworkAddress = assignedNetworkAddresses[i].getInt();
                    uint32 assignedNetworkNetmask = assignedNetworkNetmasks[i].getInt();
                    uint32 assignedNetworkAddressMaximum = assignedNetworkAddress | ~assignedNetworkNetmask;
                    EV_DEBUG << "Checking against assigned network address " << IPv4Address(assignedNetworkAddress) << endl;
                    if ((assignedNetworkAddress & ~networkAddressUnspecifiedBits) == (networkAddress & ~networkAddressUnspecifiedBits)) {
                        uint32 assignedAddressUnspecifiedPart = getPackedBits(assignedNetworkAddressMaximum, networkAddressUnspecifiedBits);
                        if (assignedAddressUnspecifiedPart > networkAddressUnspecifiedPartMaximum)
                            networkAddressUnspecifiedPartMaximum = assignedAddressUnspecifiedPart;
                    }
                }
                uint32 networkAddressUnspecifiedPartLimit = getPackedBits(0xFFFFFFFF, networkAddressUnspecifiedBits) + 1;
                EV_DEBUG << "Counting from: " << networkAddressUnspecifiedPartMaximum + 1 << " to: " << networkAddressUnspecifiedPartLimit << endl;
                // we start with +1 so that the network address will be more likely different
                for (int networkAddressUnspecifiedPart = networkAddressUnspecifiedPartMaximum; networkAddressUnspecifiedPart <= networkAddressUnspecifiedPartLimit; networkAddressUnspecifiedPart++) {
                    networkAddress = setPackedBits(networkAddress, networkAddressUnspecifiedBits, networkAddressUnspecifiedPart);
                    EV_DEBUG << "Trying network address: " << IPv4Address(networkAddress) << endl;
                    // count interfaces that have the same address prefix
                    int interfaceCount = 0;
                    for (int i = 0; i < assignedInterfaceAddresses.size(); i++)
                        if ((assignedInterfaceAddresses[i].getInt() & networkNetmask) == networkAddress)
                            interfaceCount++;
                    if (interfaceCount != 0 && par("disjunctSubnetAddresses").boolValue())
                        continue;
                    EV_DEBUG << "Matching interface count: " << interfaceCount << endl;
                    // check if there's enough room for the interface addresses
                    if ((1 << (32 - netmaskLength)) >= interfaceCount + compatibleInterfaceCount)
                        goto found;
                }
            }
            found: if (netmaskLength < minimumNetmaskLength || netmaskLength > maximumNetmaskLength)
                throw cRuntimeError("Failed to configure address prefix and netmask for %s and %d other interface(s). Please refine your parameters and try again!",
                    compatibleInterfaces[0]->interfaceEntry->getFullPath().c_str(), compatibleInterfaces.size() - 1);
            EV_DEBUG << "Selected netmask length: " << netmaskLength << endl;
            EV_DEBUG << "Selected network address: " << IPv4Address(networkAddress) << endl;
            EV_DEBUG << "Selected network netmask: " << IPv4Address(networkNetmask) << endl;

            // STEP 4.
            // determine complete IP address for all compatible interfaces
            for (int interfaceIndex = 0; interfaceIndex < compatibleInterfaces.size(); interfaceIndex++) {
                InterfaceInfo *compatibleInterface = compatibleInterfaces[interfaceIndex];
                InterfaceEntry *interfaceEntry = compatibleInterface->interfaceEntry;
                uint32 interfaceAddress = compatibleInterface->address.getInt() & ~networkNetmask;
                uint32 interfaceAddressSpecifiedBits = compatibleInterface->addressSpecifiedBits;
                uint32 interfaceAddressUnspecifiedBits = ~interfaceAddressSpecifiedBits & ~networkNetmask; // 1 means the interface address is unspecified
                uint32 interfaceAddressUnspecifiedPartMaximum = 0;
                for (int i = 0; i < assignedInterfaceAddresses.size(); i++) {
                    uint32 otherInterfaceAddress = assignedInterfaceAddresses[i].getInt();
                    if ((otherInterfaceAddress & ~interfaceAddressUnspecifiedBits) == ((networkAddress | interfaceAddress) & ~interfaceAddressUnspecifiedBits)) {
                        uint32 otherInterfaceAddressUnspecifiedPart = getPackedBits(otherInterfaceAddress, interfaceAddressUnspecifiedBits);
                        if (otherInterfaceAddressUnspecifiedPart > interfaceAddressUnspecifiedPartMaximum)
                            interfaceAddressUnspecifiedPartMaximum = otherInterfaceAddressUnspecifiedPart;
                    }
                }
                interfaceAddressUnspecifiedPartMaximum++;
                interfaceAddress = setPackedBits(interfaceAddress, interfaceAddressUnspecifiedBits, interfaceAddressUnspecifiedPartMaximum);
                // determine the complete address and netmask for interface
                IPv4Address completeAddress = IPv4Address(networkAddress | interfaceAddress);
                IPv4Address completeNetmask = IPv4Address(networkNetmask);
                // check if we could really find a unique IP address
                if (assignedAddressToInterfaceEntryMap.find(completeAddress) != assignedAddressToInterfaceEntryMap.end())
                    cRuntimeError("Failed to configure address and netmask for %s. Please refine your parameters and try again!", interfaceEntry->getFullPath().c_str());
                assignedAddressToInterfaceEntryMap[completeAddress] = compatibleInterface->interfaceEntry;
                assignedInterfaceAddresses.push_back(completeAddress);
                // configure interface with the selected address and netmask
                IPv4InterfaceData *interfaceData = compatibleInterface->interfaceEntry->ipv4Data();
                if (compatibleInterface->configure) {
                    interfaceData->setIPAddress(completeAddress);
                    interfaceData->setNetmask(completeNetmask);
                }
                compatibleInterface->address = completeAddress;
                EV_DEBUG << "Selected interface address: " << completeAddress << endl;
                // remove configured interface
                unconfiguredInterfaces.erase(find(unconfiguredInterfaces, compatibleInterface));
            }
            // register the network address and netmask as being used
            assignedNetworkAddresses.push_back(networkAddress);
            assignedNetworkNetmasks.push_back(networkNetmask);
        }
    }
}

const char *IPv4Configurator::getMandatoryAttribute(cXMLElement *element, const char *attr)
{
    const char *value = element->getAttribute(attr);
    if (isEmpty(value))
        throw cRuntimeError("<%s> element is missing mandatory attribute \"%s\" at %s", element->getTagName(), attr, element->getSourceLocation());
    return value;
}

void IPv4Configurator::addManualRoutes(cXMLElement *root, Topology& topology, NetworkInfo& networkInfo)
{
    cXMLElementList routeElements = root->getChildrenByTagName("route");
    for (int i = 0; i < routeElements.size(); i++)
    {
        cXMLElement *routeElement = routeElements[i];
        const char *hostAttr = getMandatoryAttribute(routeElement, "host");
        const char *destinationAttr = getMandatoryAttribute(routeElement, "destination"); // destination address  (IPvXAddressResolver syntax)
        const char *netmaskAttr = routeElement->getAttribute("netmask"); // default: 255.255.255.255; alternative notation: "/23"
        const char *gatewayAttr = routeElement->getAttribute("gateway"); // next hop address (IPvXAddressResolver syntax)
        const char *interfaceAttr = routeElement->getAttribute("interface"); // output interface name
        const char *metricAttr = routeElement->getAttribute("metric");

        try
        {
            // parse and check the attributes
            IPv4Address host = IPvXAddressResolver().resolve(destinationAttr, IPvXAddressResolver::ADDR_IPv4).get4();
            if (host.isUnspecified())
                throw cRuntimeError("Incomplete route: host is unspecified");
            IPv4Address netmask;
            if (isEmpty(netmaskAttr))
                netmask = IPv4Address::ALLONES_ADDRESS;
            else if (netmaskAttr[0] == '/')
                netmask = IPv4Address::makeNetmask(atoi(netmaskAttr+1));
            else
                netmask = IPv4Address(netmaskAttr);
            if (!netmask.isValidNetmask())
                throw cRuntimeError("Wrong netmask %s", netmask.str().c_str());
            if (isEmpty(interfaceAttr) && isEmpty(gatewayAttr))
                throw cRuntimeError("Incomplete route: either gateway or interface (or both) must be specified");

            // find matching host(s), and add the route
            Matcher atMatcher(hostAttr);
            for (int i = 0; i < topology.getNumNodes(); i++) {
                // extract source
                Topology::Node *node = topology.getNode(i);
                NodeInfo *nodeInfo = (NodeInfo *)node->getPayload();
                if (nodeInfo->isIPNode) {
                    std::string hostFullPath = nodeInfo->module->getFullPath();
                    std::string hostShortenedFullPath = hostFullPath.substr(hostFullPath.find('.')+1);
                    if (atMatcher.matches(hostShortenedFullPath.c_str()) || atMatcher.matches(hostFullPath.c_str())) {
                        // determine the gateway (its address towards this node!) and the output interface for the route (must be done per node)
                        InterfaceEntry *ie;
                        IPv4Address gateway;
                        resolveInterfaceAndGateway(nodeInfo, interfaceAttr, gatewayAttr, ie, gateway, networkInfo);

                        // create and add route
                        IPv4Route *route = new IPv4Route();
                        route->setDestination(host);
                        route->setNetmask(netmask);
                        route->setGateway(gateway); // may be unspecified
                        route->setInterface(ie);
                        if (isNotEmpty(metricAttr))
                            route->setMetric(atoi(metricAttr));
                        nodeInfo->routingTable->addRoute(route);
                    }
                }
            }
        }
        catch (std::exception& e)
        {
            throw cRuntimeError("Error in XML <route> element at %s: %s", routeElement->getSourceLocation(), e.what());
        }
    }
}

void IPv4Configurator::resolveInterfaceAndGateway(NodeInfo *node, const char *interfaceAttr, const char *gatewayAttr,
        InterfaceEntry *&outIE, IPv4Address& outGateway, const NetworkInfo& networkInfo)
{
    // resolve interface name
    if (isEmpty(interfaceAttr))
    {
        outIE = NULL;
    }
    else
    {
        outIE = node->interfaceTable->getInterfaceByName(interfaceAttr);
        if (!outIE)
            throw cRuntimeError("Host/router %s has no interface named \"%s\"",
                    node->module->getFullPath().c_str(), interfaceAttr);
    }

    // if gateway is not specified, we are done
    if (isEmpty(gatewayAttr))
    {
        outGateway = IPv4Address();
        return; // outInterface also already done -- we're done
    }

    ASSERT(isNotEmpty(gatewayAttr)); // see "if" above

    // check syntax of gatewayAttr, and obtain an initial value
    outGateway = IPvXAddressResolver().resolve(gatewayAttr, IPvXAddressResolver::ADDR_IPv4).get4();

    IPv4Address gatewayAddressOnCommonLink;

    if (!outIE)
    {
        // interface is not specified explicitly -- we must deduce it from the gateway.
        // It is expected that the gateway is on the same link with the configured node,
        // and then we pick the interface which connects to that link.

        // loop through all links, and find the one that contains both the
        // configured node and the gateway
        for (int i = 0; i < networkInfo.linkInfos.size(); i++)
        {
            LinkInfo *linkInfo = networkInfo.linkInfos[i];
            InterfaceInfo *gatewayInterfaceOnLink = findInterfaceOnLinkByNodeAddress(linkInfo, outGateway);
            if (gatewayInterfaceOnLink)
            {
                InterfaceInfo *nodeInterfaceOnLink = findInterfaceOnLinkByNode(linkInfo, node->module);
                if (nodeInterfaceOnLink)
                {
                    outIE = nodeInterfaceOnLink->interfaceEntry;
                    gatewayAddressOnCommonLink = gatewayInterfaceOnLink->interfaceEntry->ipv4Data()->getIPAddress(); // we may need it later
                    break;
                }
            }
        }
        if (!outIE)
            throw cRuntimeError("Host/router %s has no interface towards \"%s\"",
                    node->module->getFullPath().c_str(), gatewayAttr);
    }

    // Now we have both the interface and the gateway. Still, we may need to modify
    // the gateway address by picking the address of a different interface of the gateway --
    // the address of the interface which is towards the configured node (i.e. on the same link)
    //
    // gatewayAttr may be an IP address, or a module name, or modulename+interfacename
    // in a syntax accepted by IPvXAddressResolver. If the gatewayAttr is a concrete IP address
    // or contains a gateway interface name (IPvXAddressResolver accepts it after a "/"), we're done
    if (IPv4Address::isWellFormed(gatewayAttr) || strchr(gatewayAttr, '/') != NULL)
        return;

    // At this point, gatewayAttr must be a modulename string, so we can freely pick the
    // interface that's towards the configured node
    if (!gatewayAddressOnCommonLink.isUnspecified())
        outGateway = gatewayAddressOnCommonLink;
    else {
        // find the gateway interface that's on the same link as outIE

        // first, find which link outIE is on...
        LinkInfo *linkInfo = findLinkOfInterface(networkInfo, outIE);

        // then find which gateway interface is on that link
        InterfaceInfo *gatewayInterface = findInterfaceOnLinkByNodeAddress(linkInfo, outGateway);
        if (gatewayInterface)
            outGateway = gatewayInterface->interfaceEntry->ipv4Data()->getIPAddress();
    }
}

IPv4Configurator::InterfaceInfo *IPv4Configurator::findInterfaceOnLinkByNode(LinkInfo *linkInfo, cModule *node)
{
    for (int i = 0; i < linkInfo->interfaceInfos.size(); i++)
    {
        InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[i];
        if (interfaceInfo->interfaceEntry->getInterfaceTable()->getHostModule() == node)
            return interfaceInfo;
    }
    return NULL;
}

IPv4Configurator::InterfaceInfo *IPv4Configurator::findInterfaceOnLinkByNodeAddress(LinkInfo *linkInfo, IPv4Address address)
{
    for (int i = 0; i < linkInfo->interfaceInfos.size(); i++)
    {
        // if the interface has this address, found
        InterfaceInfo *interfaceInfo = linkInfo->interfaceInfos[i];
        if (interfaceInfo->interfaceEntry->ipv4Data()->getIPAddress() == address)
            return interfaceInfo;

        // if some other interface of the same node has the address, we accept that too
        IInterfaceTable *interfaceTable = interfaceInfo->interfaceEntry->getInterfaceTable();
        for (int j = 0; j < interfaceTable->getNumInterfaces(); j++)
            if (interfaceTable->getInterface(j)->ipv4Data()->getIPAddress() == address)
                return interfaceInfo;
    }
    return NULL;
}

IPv4Configurator::LinkInfo *IPv4Configurator::findLinkOfInterface(const NetworkInfo& networkInfo, InterfaceEntry *ie)
{
    for (int i = 0; i < networkInfo.linkInfos.size(); i++)
    {
        LinkInfo *linkInfo = networkInfo.linkInfos[i];
        for (int j = 0; j < linkInfo->interfaceInfos.size(); j++)
            if (linkInfo->interfaceInfos[j]->interfaceEntry == ie)
                return linkInfo;
    }
    return NULL;
}

static InterfaceEntry *findNextHopInterface(Topology::Node *sourceNode, Topology::Node *destinationNode, Topology::LinkOut *&link)
{
    // find next hop interface (the last IP interface on the path that is not in the source node)
    Topology::Node *node = destinationNode;
    Topology::LinkOut *nextHopLink = NULL;
    while (node != sourceNode) {
        link = node->getPath(0);
        IPv4Configurator::NodeInfo *nodeInfo = (IPv4Configurator::NodeInfo *)node->getPayload();
        if (nodeInfo->isIPNode && node != sourceNode)
            nextHopLink = link;
        node = link->getRemoteNode();
    }

    // determine next hop interface
    Topology::Node *nextHopNode = nextHopLink->getLocalNode();
    IPv4Configurator::NodeInfo *nextHopNodexInfo = (IPv4Configurator::NodeInfo *)nextHopNode->getPayload();
    IInterfaceTable *nextHopInterfaceTable = nextHopNodexInfo->interfaceTable;
    int nextHopGateId = nextHopLink->getLocalGateId();
    return nextHopInterfaceTable->getInterfaceByNodeOutputGateId(nextHopGateId);
}

void IPv4Configurator::addStaticRoutes(Topology& topology, NetworkInfo& networkInfo)
{
    long optimizeRoutesDuration = 0;
    long addDefaultRoutesDuration = 0;
    long calculateShortestPathsDuration = 0;

    // TODO: it should be configurable (via xml?) which nodes need static routes filled in automatically
    // add static routes for all routing tables
    for (int i = 0; i < topology.getNumNodes(); i++) {
        // extract source
        Topology::Node *sourceNode = topology.getNode(i);
        NodeInfo *sourceNodeInfo = (NodeInfo *)sourceNode->getPayload();
        if (!sourceNodeInfo->isIPNode)
            continue;
        IRoutingTable *sourceRoutingTable = sourceNodeInfo->routingTable;
        IInterfaceTable *sourceInterfaceTable = sourceNodeInfo->interfaceTable;

        // calculate shortest paths from everywhere to sourceNode
        // we are going to use the paths in reverse direction (assuming all links are bidirectional)
        long begin = clock();
        topology.calculateUnweightedSingleShortestPathsTo(sourceNode);
        calculateShortestPathsDuration += clock() - begin;

        // check if adding the default routes would be ok (this is an optimization)
        if (par("addDefaultRoutes").boolValue() && sourceNodeInfo->interfaceInfos.size() == 1 && sourceNodeInfo->interfaceInfos[0]->linkInfo->gatewayInterfaceInfo) {
            begin = clock();
            InterfaceInfo *sourceInterfaceInfo = sourceNodeInfo->interfaceInfos[0];
            InterfaceEntry *sourceInterfaceEntry = sourceInterfaceInfo->interfaceEntry;
            InterfaceInfo *gatewayInterfaceInfo = sourceInterfaceInfo->linkInfo->gatewayInterfaceInfo;
            InterfaceEntry *gatewayInterfaceEntry = gatewayInterfaceInfo->interfaceEntry;

            // add a network route for the local network using ARP
            IPv4Route *route = new IPv4Route();
            IPv4InterfaceData *ipv4InterfaceData = sourceInterfaceEntry->ipv4Data();
            IPv4Address address = ipv4InterfaceData->getIPAddress();
            IPv4Address netmask = ipv4InterfaceData->getNetmask();
            route->setDestination(IPv4Address(address.getInt() & netmask.getInt()));
            route->setGateway(IPv4Address::UNSPECIFIED_ADDRESS);
            route->setNetmask(netmask);
            route->setInterface(sourceInterfaceEntry);
            route->setType(IPv4Route::DIRECT);
            route->setSource(IPv4Route::MANUAL);
            sourceRoutingTable->addRoute(route);

            // add a default route towards the only one gateway
            route = new IPv4Route();
            IPv4Address gateway = gatewayInterfaceEntry->ipv4Data()->getIPAddress();
            route->setDestination(IPv4Address::UNSPECIFIED_ADDRESS);
            route->setNetmask(IPv4Address::UNSPECIFIED_ADDRESS);
            route->setGateway(gateway);
            route->setInterface(sourceInterfaceEntry);
            route->setType(IPv4Route::DIRECT);
            route->setSource(IPv4Route::MANUAL);
            sourceRoutingTable->addRoute(route);

            // skip building and optimizing the whole routing table
            EV_DEBUG << "Adding default routes to " << sourceNode->getModule()->getFullPath() << ", node has only one (non-loopback) interface\n";
            addDefaultRoutesDuration += clock() - begin;
            continue;
        }

        buildRoutes:
        std::vector<IPv4Route *> sourceRoutes;
        // add a route to all destinations in the network
        for (int j = 0; j < topology.getNumNodes(); j++) {
            if (i == j)
                continue;
            // extract destination
            Topology::Node *destinationNode = topology.getNode(j);
            if (destinationNode->getNumPaths() == 0)
                continue;
            NodeInfo *destinationNodeInfo = (NodeInfo *)destinationNode->getPayload();
            if (!destinationNodeInfo->isIPNode)
                continue;
            int destinationGateId = destinationNode->getPath(0)->getLocalGateId();
            IInterfaceTable *destinationInterfaceTable = destinationNodeInfo->interfaceTable;

            // determine next hop interface
            Topology::LinkOut *link;
            InterfaceEntry *nextHopInterfaceEntry = findNextHopInterface(sourceNode, destinationNode, link);

            // determine source interface
            Topology::LinkOut *sourceLink = link;
            int sourceGateId = sourceLink->getRemoteGateId();
            InterfaceEntry *sourceInterfaceEntry = sourceInterfaceTable->getInterfaceByNodeInputGateId(sourceGateId);

            // add the same routes for all destination interfaces (IP packets are accepted from any interface at the destination)
            for (int j = 0; j < destinationInterfaceTable->getNumInterfaces(); j++) {
                InterfaceEntry *destinationInterfaceEntry = destinationInterfaceTable->getInterface(j);
                if (!destinationInterfaceEntry->isLoopback()) {
                    IPv4Route *route = new IPv4Route();
                    IPv4Address destinationAddress = destinationInterfaceEntry->ipv4Data()->getIPAddress();
                    IPv4Address destinationNetmask = destinationInterfaceEntry->ipv4Data()->getNetmask();
                    IPv4Address gatewayAddress = nextHopInterfaceEntry->ipv4Data()->getIPAddress();
                    if (par("addSubnetRoutes").boolValue() && destinationNodeInfo->interfaceInfos.size() == 1 && destinationNodeInfo->interfaceInfos[0]->linkInfo->gatewayInterfaceInfo) {
                        route->setDestination(destinationAddress.doAnd(destinationNetmask));
                        route->setNetmask(destinationNetmask);
                    }
                    else {
                        route->setDestination(destinationAddress);
                        route->setNetmask(IPv4Address::ALLONES_ADDRESS);
                    }
                    route->setInterface(sourceInterfaceEntry);
                    if (gatewayAddress != destinationAddress)
                        route->setGateway(gatewayAddress);
                    route->setType(IPv4Route::DIRECT);
                    route->setSource(IPv4Route::MANUAL);
                    for (int k = 0; k < sourceRoutes.size(); k++)
                        if (*sourceRoutes[k] == *route)
                            goto nextInterface;
                    sourceRoutes.push_back(route);
                    EV_DEBUG << "Adding route " << sourceInterfaceEntry->getFullPath() << " -> " << destinationInterfaceEntry->getFullPath() << " as " << route->info() << endl;
                }
                nextInterface:;
            }
        }

        // optimize routing table to save memory and increase lookup performance
        if (par("optimizeRoutes").boolValue()) {
            long begin = clock();
            optimizeRoutes(&sourceRoutes);
            optimizeRoutesDuration += clock() - begin;
        }

        // copy into routing table
        for (int i = 0; i < sourceRoutes.size(); i++)
            sourceRoutingTable->addRoute(sourceRoutes[i]);
    }

    // printe some timing information
    printTimeSpentUsingDuration("calculateShortestPaths", calculateShortestPathsDuration);
    printTimeSpentUsingDuration("addDefaultRoutes", addDefaultRoutesDuration);
    printTimeSpentUsingDuration("optimizeRoutes", optimizeRoutesDuration);
}

// returns true if the two routes are the same except their address prefix and netmask
static bool routesHaveSameColor(IPv4Route *route1, IPv4Route *route2)
{
    return route1->getType() == route2->getType() && route1->getSource() == route2->getSource() && route1->getMetric() == route2->getMetric() &&
           route1->getGateway() == route2->getGateway() && route1->getInterface() == route2->getInterface();
}

// returns true if the order of the routes in the routing table does not change their meaning
static bool routesCanBeSwapped(IPv4Configurator::RouteInfo *routeInfo1, IPv4Configurator::RouteInfo *routeInfo2)
{
    if (routeInfo1->color == routeInfo2->color)
        return true;
    else {
        uint32 netmask = routeInfo1->netmask & routeInfo2->netmask;
        return (routeInfo1->destination & netmask) != (routeInfo2->destination & netmask);
    }
}

// returns true if the routes can be neighbors by repeatedly swapping routes in the routing table without changing their meaning
static bool routesCanBeNeighbors(std::vector<IPv4Configurator::RouteInfo *> *routeInfos, int i, int j)
{
    int begin = std::min(i, j);
    int end = std::max(i, j);
    IPv4Configurator::RouteInfo *beginRouteInfo = routeInfos->at(begin);
    for (int index = begin + 1; index < end; index++)
        if (!routesCanBeSwapped(beginRouteInfo, routeInfos->at(index)))
            return false;
    return true;
}

// checks if the original route is routed by the routes in the routing table between begin and end
static bool interruptsOriginalRoute(IPv4Configurator::RoutingTableInfo *routingTableInfo, int begin, int end, IPv4Configurator::RouteInfo *originalRouteInfo)
{
    IPv4Configurator::RouteInfo *matchingRouteInfo = routingTableInfo->findBestMatchingRouteInfo(originalRouteInfo->destination, begin, end);
    return matchingRouteInfo && matchingRouteInfo->color != originalRouteInfo->color;
}

// checks if any of the original routes is routed by the routes in the routing table between begin and end
static bool interruptsAnyOriginalRoute(IPv4Configurator::RoutingTableInfo *routingTableInfo, int begin, int end, std::vector<IPv4Configurator::RouteInfo *> *originalRouteInfos)
{
    if (begin < end)
        for (int i = 0; i < originalRouteInfos->size(); i++)
            if (interruptsOriginalRoute(routingTableInfo, begin, end, originalRouteInfos->at(i)))
                return true;
    return false;
}

// checks if the original routes attached to the routes in the table below index are interrupted by the route at index
static bool interruptsFollowingOriginalRoutes(IPv4Configurator::RoutingTableInfo *routingTableInfo, int index)
{
    for (int i = index + 1; i < routingTableInfo->routeInfos.size(); i++) {
        IPv4Configurator::RouteInfo *routeInfo = routingTableInfo->routeInfos.at(i);
        if (interruptsAnyOriginalRoute(routingTableInfo, index, index + 1, &routeInfo->originalRouteInfos))
            return true;
    }
    return false;
}

static void checkOriginalRoutes(IPv4Configurator::RoutingTableInfo *routingTableInfo, std::vector<IPv4Configurator::RouteInfo *> *originalRouteInfos)
{
    // assert that all original routes are routed with the same color
    for (int i = 0; i < originalRouteInfos->size(); i++) {
        IPv4Configurator::RouteInfo *originalRouteInfo = originalRouteInfos->at(i);
        IPv4Configurator::RouteInfo *matchingRouteInfo = routingTableInfo->findBestMatchingRouteInfo(originalRouteInfo->destination);
        if (!(matchingRouteInfo && matchingRouteInfo->color == originalRouteInfo->color))
            ASSERT(false);
    }
}

void IPv4Configurator::optimizeRoutes(std::vector<IPv4Route *> *originalRoutes)
{
    RoutingTableInfo routingTableInfo;
    std::vector<IPv4Route *> colorToRouteColor;
    std::vector<RouteInfo *> originalRouteInfos;
    // build colorToRouteColor, originalRouteInfos and initial routeInfos in routingTableInfo
    for (int i = 0; i < originalRoutes->size(); i++) {
        IPv4Route *originalRoute = originalRoutes->at(i);
        // originalRouteInfo
        RouteInfo *originalRouteInfo = new RouteInfo(colorToRouteColor.size(), originalRoute->getDestination().getInt(), originalRoute->getNetmask().getInt());
        originalRouteInfos.push_back(originalRouteInfo);
        for (int j = 0; j < colorToRouteColor.size(); j++) {
            if (routesHaveSameColor(colorToRouteColor[j], originalRoute)) {
                originalRouteInfo->color = j;
                goto next;
            }
        }
        colorToRouteColor.push_back(originalRoute);
        next:;
        // initial optimized route info
        RouteInfo *optimizedRouteInfo = new RouteInfo(*originalRouteInfo);
        optimizedRouteInfo->originalRouteInfos.push_back(originalRouteInfo);
        routingTableInfo.addRouteInfo(optimizedRouteInfo);
    }
#ifndef NDEBUG
    checkOriginalRoutes(&routingTableInfo, &originalRouteInfos);
#endif
    restart:
    // check if any two routes can be aggressively merged without changing the meaning of all original routes
    // the merged route will have the longest shared address prefix and netmask with the two merged routes
    // this optimization might change the meaning of the routing table in that it will route packets that it did not route before
    for (int i = 0; i < routingTableInfo.routeInfos.size(); i++) {
        RouteInfo *routeInfoI = routingTableInfo.routeInfos.at(i);
        // iterate backward so that we try to merge longer netmasks first
        // this results in smaller changes and allows more symmetric optimization
        for (int j = i - 1; j >= 0; j--) {
            RouteInfo *routeInfoJ = routingTableInfo.routeInfos.at(j);
            // merge only neighbor routes having the same color
            if (routeInfoI->color == routeInfoJ->color && routesCanBeNeighbors(&routingTableInfo.routeInfos, i, j)) {
                // determine longest shared address prefix and netmask by iterating through bits from left to right
                uint32 netmask = 0;
                uint32 destination = 0;
                for (int bitIndex = 31; bitIndex >= 0; bitIndex--) {
                    uint32 mask = 1 << bitIndex;
                    if ((routeInfoI->destination & mask) == (routeInfoJ->destination & mask) &&
                        (routeInfoI->netmask & mask) != 0 && (routeInfoJ->netmask & mask) != 0)
                    {
                        netmask |= mask;
                        destination |= routeInfoI->destination & mask;
                    }
                    else
                        break;
                }
                // create the merged route
                RouteInfo *mergedRouteInfo = new RouteInfo(routeInfoI->color, destination, netmask);
                routeInfoI->enabled = false;
                routeInfoJ->enabled = false;
                int m = routingTableInfo.addRouteInfo(mergedRouteInfo);
                ASSERT(m > i && m > j);
                // check if all the original routes are still routed the same way
                // optimization: instead of checking all routes, check only those which can go wrong due to the merge (assuming the previous configuration was correct)
                //  - the routes on I and J are going to be routed by M after the merge, so check if the routes in between don't interrupt
                //  - the routes following M can be accidentally overridden by M (being larger than the sum of I and J), so verify that M does not interrupt
                // note that the condition is not symmetric because I follows J so it requires fewer checks
                if (!interruptsAnyOriginalRoute(&routingTableInfo, j + 1, i, &routeInfoJ->originalRouteInfos) && // check that original routes on J are not interrupted between J and I
                    !interruptsAnyOriginalRoute(&routingTableInfo, i + 1, m, &routeInfoJ->originalRouteInfos) && // check that original routes on J are not interrupted between I and M
                    !interruptsAnyOriginalRoute(&routingTableInfo, i + 1, m, &routeInfoI->originalRouteInfos) && // check that original routes on I are not interrupted between I and M
                    !interruptsFollowingOriginalRoutes(&routingTableInfo, m)) // check that the original routes after M are not interrupted by M
                {
                    // move originalRouteInfos from the to be deleted route
                    for (int k = 0; k < routeInfoI->originalRouteInfos.size(); k++) {
                        RouteInfo *originalRouteInfo = routeInfoI->originalRouteInfos.at(k);
                        IPv4Configurator::RouteInfo *matchingRouteInfo = routingTableInfo.findBestMatchingRouteInfo(originalRouteInfo->destination, i + 1, m + 1);
                        ASSERT(matchingRouteInfo && matchingRouteInfo->color == originalRouteInfo->color);
                        matchingRouteInfo->originalRouteInfos.push_back(originalRouteInfo);
                    }
                    // move originalRouteInfos from the to be deleted route
                    for (int k = 0; k < routeInfoJ->originalRouteInfos.size(); k++) {
                        RouteInfo *originalRouteInfo = routeInfoJ->originalRouteInfos.at(k);
                        IPv4Configurator::RouteInfo *matchingRouteInfo = routingTableInfo.findBestMatchingRouteInfo(originalRouteInfo->destination, j + 1, m + 1);
                        ASSERT(matchingRouteInfo && matchingRouteInfo->color == originalRouteInfo->color);
                        matchingRouteInfo->originalRouteInfos.push_back(originalRouteInfo);
                    }
                    // move originalRouteInfos from the following routes if necessary
                    for (int k = m + 1; k < routingTableInfo.routeInfos.size(); k++) {
                        RouteInfo *followingRouteInfo = routingTableInfo.routeInfos.at(k);
                        for (int l = 0; l < followingRouteInfo->originalRouteInfos.size(); l++) {
                            RouteInfo *originalRouteInfo = followingRouteInfo->originalRouteInfos.at(l);
                            if (!((originalRouteInfo->destination ^ mergedRouteInfo->destination) & mergedRouteInfo->netmask)) {
                                followingRouteInfo->originalRouteInfos.erase(followingRouteInfo->originalRouteInfos.begin() + l);
                                ASSERT(mergedRouteInfo->color == originalRouteInfo->color);
                                mergedRouteInfo->originalRouteInfos.push_back(originalRouteInfo);
                                l--;
                            }
                        }
                    }
                    routingTableInfo.removeRouteInfo(routeInfoI);
                    routingTableInfo.removeRouteInfo(routeInfoJ);
#ifndef NDEBUG
                    //checkOriginalRoutes(&routingTableInfo, &originalRouteInfos);
#endif
                    delete routeInfoI;
                    delete routeInfoJ;
                }
                else {
                    routeInfoI->enabled = true;
                    routeInfoJ->enabled = true;
                    routingTableInfo.removeRouteInfo(mergedRouteInfo);
                    delete mergedRouteInfo;
                    goto nextPair;
                }
                goto restart;
            }
            nextPair:;
        }
    }
#ifndef NDEBUG
    checkOriginalRoutes(&routingTableInfo, &originalRouteInfos);
#endif
    // convert route infos to new routes based on color
    std::vector<IPv4Route *> optimizedRoutes;
    for (int i = 0; i < routingTableInfo.routeInfos.size(); i++) {
        RouteInfo *routeInfo = routingTableInfo.routeInfos.at(i);
        IPv4Route *routeColor = colorToRouteColor[routeInfo->color];
        IPv4Route *optimizedRoute = new IPv4Route();
        optimizedRoute->setDestination(routeInfo->destination);
        optimizedRoute->setNetmask(routeInfo->netmask);
        optimizedRoute->setInterface(routeColor->getInterface());
        optimizedRoute->setGateway(routeColor->getGateway());
        optimizedRoute->setType(routeColor->getType());
        optimizedRoute->setSource(routeColor->getSource());
        optimizedRoutes.push_back(optimizedRoute);
        delete routeInfo;
    }
    // delete original routes
    for (int i = 0; i < originalRoutes->size(); i++)
        delete originalRoutes->at(i);
    // copy optimized routes to original routes and return
    *originalRoutes = optimizedRoutes;
}
