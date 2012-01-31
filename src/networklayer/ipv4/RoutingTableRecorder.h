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

#ifndef __ROUTINGTABLERECORDER_H
#define __ROUTINGTABLERECORDER_H

#include "INETDefs.h"
#include "IRoutingTable.h"
#include "INotifiable.h"

/**
 * Records routing table changes into a file.
  *
 * @see RoutingTable, IPv4Route
 */
class INET_API RoutingTableRecorder : public cSimpleModule, protected INotifiable
{
  private:
    FILE *routingLogFile;

  public:
    RoutingTableRecorder();
    virtual ~RoutingTableRecorder();

  protected:
    virtual int numInitStages() const  {return 1;}
    virtual void initialize(int stage);
    virtual void handleMessage(cMessage *);
    virtual void hookListeners();
    virtual void receiveChangeNotification(int category, const cObject *details);
    virtual void ensureRoutingLogFileOpen();
    virtual void recordInterfaceChange(int category, const InterfaceEntry *ie);
    virtual void recordRouteChange(int category, const IPv4Route *route);
};

#endif

