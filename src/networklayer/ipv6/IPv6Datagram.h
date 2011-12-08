//
// Copyright (C) 2005 Andras Varga
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


#ifndef _IPv6DATAGRAM_H_
#define _IPv6DATAGRAM_H_

#include <list>
#include "INETDefs.h"
#include "IPv6Datagram_m.h"

/**
 * Represents an IPv6 datagram. More info in the IPv6Datagram.msg file
 * (and the documentation generated from it).
 */
class INET_API IPv6Datagram : public IPv6Datagram_Base
{
  protected:
    typedef std::vector<IPv6ExtensionHeader*> ExtensionHeaders;
    ExtensionHeaders extensionHeaders;

  private:
    void copy(const IPv6Datagram& other);
    void clean();

  public:
    IPv6Datagram(const char *name = NULL, int kind = 0) : IPv6Datagram_Base(name, kind) {}
    IPv6Datagram(const IPv6Datagram& other) : IPv6Datagram_Base(other) { copy(other); }
    IPv6Datagram& operator=(const IPv6Datagram& other);
    ~IPv6Datagram();

    virtual IPv6Datagram *dup() const {return new IPv6Datagram(*this);}

    /**
     * Returns bits 0-5 of the Traffic Class field, a value in the 0..63 range
     */
    virtual int getDiffServCodePoint() const { return getTrafficClass() & 0x3f; }

    /**
     * Sets bits 0-5 of the Traffic Class field; expects a value in the 0..63 range
     */
    virtual void setDiffServCodePoint(int dscp)  { setTrafficClass( (getTrafficClass() & 0xc0) | (dscp & 0x3f)); }

    /**
     * Returns bits 6-7 of the Traffic Class field, a value in the range 0..3
     */
    virtual int getExplicitCongestionNotification() const  { return (getTrafficClass() >> 6) & 0x03; }

    /**
     * Sets bits 6-7 of the Traffic Class field; expects a value in the 0..3 range
     */
    virtual void setExplicitCongestionNotification(int ecn)  { setTrafficClass( (getTrafficClass() & 0x3f) | ((ecn & 0x3) << 6)); }

    /** Generated but unused method, should not be called. */
    virtual void setExtensionHeaderArraySize(unsigned int size);

    /** Generated but unused method, should not be called. */
    virtual void setExtensionHeader(unsigned int k, const IPv6ExtensionHeaderPtr& extensionHeader_var);

    /**
     * Returns the number of extension headers in this datagram
     */
    virtual unsigned int getExtensionHeaderArraySize() const;

    /**
     * Returns the kth extension header in this datagram
     */
    virtual IPv6ExtensionHeaderPtr& getExtensionHeader(unsigned int k);

    /**
     * Adds an extension header to the datagram, at the given position.
     * The default (atPos==-1) is to add the header at the end.
     */
    virtual void addExtensionHeader(IPv6ExtensionHeader *eh, int atPos = -1);

    /**
     * Calculates the length of the IPv6 header plus the extension
     * headers.
     */
    virtual int calculateHeaderByteLength() const;

    /**
     * Removes and returns the first extension header of this datagram
     */
    virtual IPv6ExtensionHeader* removeFirstExtensionHeader();
};

#endif


