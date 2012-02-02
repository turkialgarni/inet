//
// Copyright (C) 2004-2006 Andras Varga
// Copyright (C) 2000 Institut fuer Telematik, Universitaet Karlsruhe
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

#include <stdio.h>
#include <sstream>

#include "IPv4Route.h"
#include "IPv4InterfaceData.h"

#include "InterfaceEntry.h"
#include "IRoutingTable.h"


IPv4Route::IPv4Route()
{
    rt = NULL;
    interfacePtr = NULL;
    metric = 0;
    type = DIRECT;
    source = MANUAL;
}

std::string IPv4Route::info() const
{
    std::stringstream out;

    out << "dest:"; if (dest.isUnspecified()) out << "*  "; else out << dest << "  ";
    out << "gw:"; if (gateway.isUnspecified()) out << "*  "; else out << gateway << "  ";
    out << "mask:"; if (netmask.isUnspecified()) out << "*  "; else out << netmask << "  ";
    out << "metric:" << metric << " ";
    out << "if:"; if (!interfacePtr) out << "*  "; else out << interfacePtr->getName() << "(" << interfacePtr->ipv4Data()->getIPAddress() << ")  ";
    out << (type==DIRECT ? "DIRECT" : "REMOTE");


    switch (source)
    {
        case MANUAL:       out << " MANUAL"; break;
        case IFACENETMASK: out << " IFACENETMASK"; break;
        case RIP:          out << " RIP"; break;
        case OSPF:         out << " OSPF"; break;
        case BGP:          out << " BGP"; break;
        case ZEBRA:        out << " ZEBRA"; break;
        case MANET:        out << " MANET"; break;
        default:           out << " ???"; break;
    }

    return out.str();
}

std::string IPv4Route::detailedInfo() const
{
    return std::string();
}

bool IPv4Route::equals(const IPv4Route& route) const
{
    return rt == route.rt && dest == route.dest && netmask == route.netmask && gateway == route.gateway &&
           interfacePtr == route.interfacePtr && type == route.type && source == route.source && metric == route.metric;
}

const char *IPv4Route::getInterfaceName() const
{
    return interfacePtr ? interfacePtr->getName() : "";
}

void IPv4Route::changed(int fieldCode)
{
    if (rt)
        rt->routeChanged(this, fieldCode);
}
