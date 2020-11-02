// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "serialize.h"
#include "netbase.h"
#include <string>
#include "uint256.h"

extern bool fTestNet;
static inline unsigned short GetDefaultPort(const bool testnet = fTestNet)
{
    return testnet ? 25298 : 15298;
}


extern unsigned char pchMessageStart[4];

/* Message header
 * (4 bytes) message start aka network magic number
 * (12 bytes) command, null terminated
 * (4 bytes) message size
 * (4 bytes) message checksum */
class CMessageHeader {
    public:
        static const uint MESSAGE_START_SIZE = 4;
        static const uint COMMAND_SIZE = 12;
        static const uint MESSAGE_SIZE_SIZE = 4;
        static const uint CHECKSUM_SIZE = 4;
        static const uint MESSAGE_SIZE_OFFSET = MESSAGE_START_SIZE + COMMAND_SIZE;
        static const uint CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE;

        CMessageHeader();
        CMessageHeader(const char *pszCommand, uint nMessageSizeIn);

        bool IsCommandValid() const;

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(pchMessageStart));
             READWRITE(FLATDATA(pchCommand));
             READWRITE(nMessageSize);
             READWRITE(nChecksum);
            )

        char pchMessageStart[MESSAGE_START_SIZE];
        char pchCommand[COMMAND_SIZE];
        uint nMessageSize;
        uint nChecksum;
};

/** nServices flags */
enum
{
    NODE_NETWORK = (1 << 0),
};

/** A CService with information about it as peer */
class CAddress : public CService
{
    public:
        CAddress();
        explicit CAddress(CService ipIn, uint64 nServicesIn=NODE_NETWORK);

        void Init();

        IMPLEMENT_SERIALIZE
            (
             CAddress* pthis = const_cast<CAddress*>(this);
             CService* pip = (CService*)pthis;
             if (fRead)
                 pthis->Init();
             if(nType & SER_DISK) {
                 READWRITE(nVersion);
                 READWRITE(nTime);
             }
             READWRITE(nServices);
             READWRITE(*pip);
            )

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64 nServices;

        // disk and network only
        unsigned int nTime;

        // memory only
        int64 nLastTry;
};

/** inv message data */
class CInv
{
    public:
        CInv();
        CInv(int typeIn, const uint256& hashIn);
        CInv(const std::string& strType, const uint256& hashIn);

        IMPLEMENT_SERIALIZE
        (
            READWRITE(type);
            READWRITE(hash);
        )

        friend bool operator<(const CInv& a, const CInv& b);

        bool IsKnownType() const;
        const char* GetCommand() const;
        std::string ToString() const;
        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        int type;
        uint256 hash;
};

#endif /* PROTOCOL_H */
