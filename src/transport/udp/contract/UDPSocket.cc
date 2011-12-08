//
// Copyright (C) 2005,2011 Andras Varga
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

#include "UDPSocket.h"
#include "UDPControlInfo_m.h"


UDPSocket::UDPSocket()
{
    // don't allow user-specified sockIds because they may conflict with
    // automatically assigned ones.
    sockId = generateSocketId();
    gateToUdp = NULL;
}

int UDPSocket::generateSocketId()
{
    return ev.getUniqueNumber();
}

void UDPSocket::sendToUDP(cMessage *msg)
{
    if (!gateToUdp)
        throw cRuntimeError("UDPSocket: setOutputGate() must be invoked before socket can be used");

    check_and_cast<cSimpleModule *>(gateToUdp->getOwnerModule())->send(msg, gateToUdp);
}

void UDPSocket::bind(int localPort)
{
    bind(IPvXAddress(), localPort);
}

void UDPSocket::bind(IPvXAddress localAddr, int localPort)
{
    if (localPort<-1 || localPort>65535)  // -1: ephemeral port
        throw cRuntimeError("UDPSocket::bind(): invalid port number %d", localPort);

    UDPBindCommand *ctrl = new UDPBindCommand();
    ctrl->setSockId(sockId);
    ctrl->setLocalAddr(localAddr);
    ctrl->setLocalPort(localPort);
    cMessage *msg = new cMessage("BIND", UDP_C_BIND);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::connect(IPvXAddress addr, int port)
{
    if (addr.isUnspecified())
        throw cRuntimeError("UDPSocket::connect(): unspecified remote address");
    if (port<=0 || port>65535)
        throw cRuntimeError("UDPSocket::connect(): invalid remote port number %d", port);

    UDPConnectCommand *ctrl = new UDPConnectCommand();
    ctrl->setSockId(sockId);
    ctrl->setRemoteAddr(addr);
    ctrl->setRemotePort(port);
    cMessage *msg = new cMessage("CONNECT", UDP_C_CONNECT);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::sendTo(cPacket *pk, IPvXAddress destAddr, int destPort)
{
    pk->setKind(UDP_C_DATA);
    UDPSendCommand *ctrl = new UDPSendCommand();
    ctrl->setSockId(sockId);
    ctrl->setDestAddr(destAddr);
    ctrl->setDestPort(destPort);
    pk->setControlInfo(ctrl);
    sendToUDP(pk);
}

void UDPSocket::send(cPacket *pk)
{
    pk->setKind(UDP_C_DATA);
    UDPSendCommand *ctrl = new UDPSendCommand();
    ctrl->setSockId(sockId);
    pk->setControlInfo(ctrl);
    sendToUDP(pk);
}

void UDPSocket::close()
{
    cMessage *msg = new cMessage("CLOSE", UDP_C_CLOSE);
    UDPCloseCommand *ctrl = new UDPCloseCommand();
    ctrl->setSockId(sockId);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::setBroadcast(bool broadcast)
{
    cMessage *msg = new cMessage("SetBroadcast", UDP_C_SETOPTION);
    UDPSetBroadcastCommand *ctrl = new UDPSetBroadcastCommand();
    ctrl->setSockId(sockId);
    ctrl->setBroadcast(broadcast);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::setTimeToLive(int ttl)
{
    cMessage *msg = new cMessage("SetTTL", UDP_C_SETOPTION);
    UDPSetTimeToLiveCommand *ctrl = new UDPSetTimeToLiveCommand();
    ctrl->setSockId(sockId);
    ctrl->setTtl(ttl);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::setDiffServCodePoint(int dscp)
{
    cMessage *msg = new cMessage("SetDSCP", UDP_C_SETOPTION);
    UDPSetDiffServCodePointCommand *ctrl = new UDPSetDiffServCodePointCommand();
    ctrl->setSockId(sockId);
    ctrl->setDscp(dscp);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::setMulticastOutputInterface(int interfaceId)
{
    cMessage *msg = new cMessage("SetMulticastOutputIf", UDP_C_SETOPTION);
    UDPSetMulticastInterfaceCommand *ctrl = new UDPSetMulticastInterfaceCommand();
    ctrl->setSockId(sockId);
    ctrl->setInterfaceId(interfaceId);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::joinMulticastGroup(const IPvXAddress& multicastAddr, int interfaceId)
{
    cMessage *msg = new cMessage("JoinMulticastGroup", UDP_C_SETOPTION);
    UDPJoinMulticastGroupCommand *ctrl = new UDPJoinMulticastGroupCommand();
    ctrl->setSockId(sockId);
    ctrl->setMulticastAddr(multicastAddr);
    ctrl->setInterfaceId(interfaceId);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

void UDPSocket::leaveMulticastGroup(const IPvXAddress& multicastAddr)
{
    cMessage *msg = new cMessage("LeaveMulticastGroup", UDP_C_SETOPTION);
    UDPLeaveMulticastGroupCommand *ctrl = new UDPLeaveMulticastGroupCommand();
    ctrl->setSockId(sockId);
    ctrl->setMulticastAddr(multicastAddr);
    msg->setControlInfo(ctrl);
    sendToUDP(msg);
}

bool UDPSocket::belongsToSocket(cMessage *msg)
{
    return dynamic_cast<UDPControlInfo *>(msg->getControlInfo()) &&
           ((UDPControlInfo *)(msg->getControlInfo()))->getSockId()==sockId;
}

bool UDPSocket::belongsToAnyUDPSocket(cMessage *msg)
{
    return dynamic_cast<UDPControlInfo *>(msg->getControlInfo());
}

std::string UDPSocket::getReceivedPacketInfo(cPacket *pk)
{
    UDPDataIndication *ctrl = check_and_cast<UDPDataIndication *>(pk->getControlInfo());

    IPvXAddress srcAddr = ctrl->getSrcAddr();
    IPvXAddress destAddr = ctrl->getDestAddr();
    int srcPort = ctrl->getSrcPort();
    int destPort = ctrl->getDestPort();

    std::stringstream os;
    os  << pk << "  (" << pk->getByteLength() << " bytes)" << endl;
    os  << srcAddr << " :" << srcPort << " --> " << destAddr << ":" << destPort << endl;
    return os.str();
}

