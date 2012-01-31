//
// Copyright (C) 2012 Andras Varga
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


#include "NotifierConsts.h"
#include "NotificationBoard.h"
#include "IRoutingTable.h"
#include "IPv4Route.h"
#include "IInterfaceTable.h"
#include "IPv4InterfaceData.h"
#include "RoutingTableRecorder.h"


Define_Module(RoutingTableRecorder);

#define LL INT64_PRINTF_FORMAT  // for eventnumber_t

Register_PerRunConfigOption(CFGID_ROUTINGLOG_FILE, "routinglog-file", CFG_FILENAME, "${resultdir}/${configname}-${runnumber}.rt", "Name of the routing log file to generate.");


RoutingTableRecorder::RoutingTableRecorder()
{
    routingLogFile = NULL;
}

RoutingTableRecorder::~RoutingTableRecorder()
{
}

void RoutingTableRecorder::initialize(int stage)
{
    if (par("enabled").boolValue())
        hookListeners();
}

void RoutingTableRecorder::handleMessage(cMessage *)
{
    throw cRuntimeError(this, "This module doesn't process messages");
}

void RoutingTableRecorder::hookListeners()
{
    // hook existing notification boards (we won't cover dynamically created hosts/routers, but oh well)
    for (int id = 0; id < simulation.getLastModuleId(); id++)
    {
        NotificationBoard *nb = dynamic_cast<NotificationBoard *>(simulation.getModule(id));
        if (nb)
        {
            nb->subscribe(this, NF_INTERFACE_CREATED);
            nb->subscribe(this, NF_INTERFACE_DELETED);
            nb->subscribe(this, NF_INTERFACE_CONFIG_CHANGED);
            nb->subscribe(this, NF_INTERFACE_IPv4CONFIG_CHANGED);
            //nb->subscribe(this, NF_INTERFACE_IPv6CONFIG_CHANGED);
            //nb->subscribe(this, NF_INTERFACE_STATE_CHANGED);

            nb->subscribe(this, NF_IPv4_ROUTE_ADDED);
            nb->subscribe(this, NF_IPv4_ROUTE_DELETED);
            nb->subscribe(this, NF_IPv4_ROUTE_CHANGED);
        }
    }
}

void RoutingTableRecorder::ensureRoutingLogFileOpen()
{
    if (routingLogFile == NULL)
    {
        // hack to ensure that results/ folder is created
        simulation.getSystemModule()->recordScalar("hackForCreateResultsFolder", 0);

        std::string fname = ev.getConfig()->getAsFilename(CFGID_ROUTINGLOG_FILE);
        routingLogFile = fopen(fname.c_str(), "w");
        if (!routingLogFile)
            throw cRuntimeError("Cannot open file %s", fname);
    }
}

void RoutingTableRecorder::receiveChangeNotification(int category, const cObject *details)
{
    if (category==NF_IPv4_ROUTE_ADDED || category==NF_IPv4_ROUTE_DELETED || category==NF_IPv4_ROUTE_CHANGED)
        recordRouteChange(category, check_and_cast<const IPv4Route *>(details));
    else
        recordInterfaceChange(category, check_and_cast<const InterfaceEntry *>(details));
}

void RoutingTableRecorder::recordInterfaceChange(int category, const InterfaceEntry *entry)
{
    IInterfaceTable *ift = entry->getInterfaceTable();
    cModule *host = ift->getHostModule();

    const char *tag;
    switch (category) {
    case NF_INTERFACE_CREATED: tag = "+I"; break;
    case NF_INTERFACE_DELETED: tag = "-I"; break;
    case NF_INTERFACE_CONFIG_CHANGED: tag = "*I"; break;
    case NF_INTERFACE_IPv4CONFIG_CHANGED: tag = "*I"; break;
    default: throw cRuntimeError("Unexpected notification category %d", category);
    }

    // time, moduleId, ifname, address
    ensureRoutingLogFileOpen();
    fprintf(routingLogFile, "%s  %"LL"d  %s  %d  %s %s\n",
            tag,
            simulation.getEventNumber(),
            SIMTIME_STR(simTime()),
            host->getId(),
            entry->getName(),
            (entry->ipv4Data()!=NULL ? entry->ipv4Data()->getIPAddress().str().c_str() : "")
            );
    fflush(routingLogFile);
}

void RoutingTableRecorder::recordRouteChange(int category, const IPv4Route *route)
{
    IRoutingTable *rt = route->getRoutingTable();
    cModule *host = rt->getHostModule();

    const char *tag;
    switch (category) {
    case NF_IPv4_ROUTE_ADDED: tag = "+R"; break;
    case NF_IPv4_ROUTE_CHANGED: tag = "*R"; break;
    case NF_IPv4_ROUTE_DELETED: tag = "-R"; break;
    default: throw cRuntimeError("Unexpected notification category %d", category);
    }

    // time, moduleId, routerID, dest, dest netmask, nexthop
    ensureRoutingLogFileOpen();
    fprintf(routingLogFile, "%s %"LL"d  %s  %d  %s  %s  %s  %s\n",
            tag,
            simulation.getEventNumber(),
            SIMTIME_STR(simTime()),
            host->getId(),
            rt->getRouterId().str().c_str(),
            route->getDestination().str().c_str(),
            route->getNetmask().str().c_str(),
            route->getGateway().str().c_str()
    );
    fflush(routingLogFile);
}


//TODO: routerID change
//    // time, moduleId, routerID
//    ensureRoutingLogFileOpen();
//    fprintf(routingLogFile, "ID  %s  %d  %s\n",
//            SIMTIME_STR(simTime()),
//            getParentModule()->getId(), //XXX we assume routing table is direct child of the node compound module
//            a.str().c_str()
//            );
//    fflush(routingLogFile);
//}
