/*
 * Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "EtherHub.h"


Define_Module(EtherHub);

//TODO
// For checking datarates and connections when changed these, you must add a listener
// of POST_MODEL_CHANGE signal and recheck settings when created a new connection or changed a
// datarate parameter. When a new connection created, the module receives two signal:
// one signal for incoming and one for outgoing gate.
// See it in EtherMACBase, EtherMAC, EtherMACFullDuplex modules.


simsignal_t EtherHub::pkSignal = SIMSIGNAL_NULL;

static cEnvir& operator<<(cEnvir& out, cMessage *msg)
{
    out.printf("(%s)%s", msg->getClassName(), msg->getFullName());
    return out;
}

void EtherHub::initialize()
{
    numMessages = 0;
    WATCH(numMessages);

    pkSignal = registerSignal("pk");

    checkConnections();
}

void EtherHub::checkConnections()
{
    ports = gateSize("ethg");
    int activePorts = 0;

    double datarate = 0.0;

    for (int i=0; i < ports; i++)
    {
        cGate* igate = gate("ethg$i", i);
        cGate* ogate = gate("ethg$o", i);
        if (!(igate->isConnected() && ogate->isConnected()))
            continue;

        activePorts++;
        double drate = igate->getIncomingTransmissionChannel()->getNominalDatarate();

        if (activePorts == 1)
            datarate = drate;
        else if (datarate != drate)
            throw cRuntimeError(this, "The input datarate at port %i differs from datarates of previous ports", i);

        drate = gate("ethg$o", i)->getTransmissionChannel()->getNominalDatarate();

        if (datarate != drate)
            throw cRuntimeError(this, "The output datarate at port %i differs from datarates of previous ports", i);

        igate->setDeliverOnReceptionStart(true);
    }
}

void EtherHub::handleMessage(cMessage *msg)
{
    // Handle frame sent down from the network entity: send out on every other port
    int arrivalPort = msg->getArrivalGate()->getIndex();
    EV << "Frame " << msg << " arrived on port " << arrivalPort << ", broadcasting on all other ports\n";

    numMessages++;
    emit(pkSignal, msg);

    if (ports <= 1)
    {
        delete msg;
        return;
    }

    for (int i=0; i < ports; i++)
    {
        if (i != arrivalPort)
        {
            cGate* igate = gate("ethg$i", i);
            cGate* ogate = gate("ethg$o", i);
            if (!(igate->isConnected() && ogate->isConnected()))
                continue;

            bool isLast = (arrivalPort == ports-1) ? (i == ports-2) : (i == ports-1);
            cMessage *msg2 = isLast ? msg : (cMessage*) msg->dup();

            // stop current transmission
            ogate->getTransmissionChannel()->forceTransmissionFinishTime(SIMTIME_ZERO);

            // send
            send(msg2, ogate);

            if (isLast)
                msg = NULL;  // msg sent, do not delete it.
        }
    }
    delete msg;
}

void EtherHub::finish()
{
    simtime_t t = simTime();
    recordScalar("simulated time", t);

    if (t > 0)
        recordScalar("messages/sec", numMessages / t);
}

