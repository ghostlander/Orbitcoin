// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCRIPT_H
#define SCRIPT_H

#include <string>
#include <vector>

#include <boost/foreach.hpp>

#include "keystore.h"
#include "bignum.h"

/* Threshold for nLockTime: below this value it is interpreted as block number,
 * otherwise as UNIX timestamp */
static const uint LOCKTIME_THRESHOLD = 500000000; /* 5 Nov 1985 00:53:20 1985 UTC */

std::string ScriptToAsmStr(const CScript &script, const bool fAttemptSighashDecode = false);
bool ParseScript(const std::string &source, CScript &result);

class CCoins;
class CTransaction;

typedef std::vector<uchar> valtype;

template <typename T>
std::vector<uchar> ToByteVector(const T &in) {
    return(std::vector<uchar>(in.begin(), in.end()));
}

/** Signature hash types/flags */
enum {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/* Script verification flags */
enum {
    SCRIPT_VERIFY_NONE      = 0,
    SCRIPT_VERIFY_P2SH      = (1U << 0),
    SCRIPT_VERIFY_STRICTENC = (1U << 1),
    SCRIPT_VERIFY_DERSIG    = (1U << 2),
    SCRIPT_VERIFY_LOCKTIME  = (1U << 3),
};

/* IsMine() return codes */
enum isminetype {
    MINE_NO = 0,
    MINE_WATCH_ONLY = 1,
    MINE_SPENDABLE = 2,
};

enum txnouttype {
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
};

const char* GetTxnOutputType(txnouttype t);

/** Script opcodes */
enum opcodetype {
    // push value
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_PUSHDATA1 = 0x4C,
    OP_PUSHDATA2 = 0x4D,
    OP_PUSHDATA4 = 0x4E,
    OP_1NEGATE = 0x4F,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_TRUE=OP_1,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5A,
    OP_11 = 0x5B,
    OP_12 = 0x5C,
    OP_13 = 0x5D,
    OP_14 = 0x5E,
    OP_15 = 0x5F,
    OP_16 = 0x60,

    // control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6A,

    // stack ops
    OP_TOALTSTACK = 0x6B,
    OP_FROMALTSTACK = 0x6C,
    OP_2DROP = 0x6D,
    OP_2DUP = 0x6E,
    OP_3DUP = 0x6F,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7A,
    OP_ROT = 0x7B,
    OP_SWAP = 0x7C,
    OP_TUCK = 0x7D,

    // splice ops
    OP_CAT = 0x7E,
    OP_SUBSTR = 0x7F,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,

    // bit logic
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8A,

    // numeric
    OP_1ADD = 0x8B,
    OP_1SUB = 0x8C,
    OP_2MUL = 0x8D,
    OP_2DIV = 0x8E,
    OP_NEGATE = 0x8F,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,

    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,

    OP_BOOLAND = 0x9A,
    OP_BOOLOR = 0x9B,
    OP_NUMEQUAL = 0x9C,
    OP_NUMEQUALVERIFY = 0x9D,
    OP_NUMNOTEQUAL = 0x9E,
    OP_LESSTHAN = 0x9F,
    OP_GREATERTHAN = 0xA0,
    OP_LESSTHANOREQUAL = 0xA1,
    OP_GREATERTHANOREQUAL = 0xA2,
    OP_MIN = 0xA3,
    OP_MAX = 0xA4,

    OP_WITHIN = 0xA5,

    // crypto
    OP_RIPEMD160 = 0xA6,
    OP_SHA1 = 0xA7,
    OP_SHA256 = 0xA8,
    OP_HASH160 = 0xA9,
    OP_HASH256 = 0xAA,
    OP_CODESEPARATOR = 0xAB,
    OP_CHECKSIG = 0xAC,
    OP_CHECKSIGVERIFY = 0xAD,
    OP_CHECKMULTISIG = 0xAE,
    OP_CHECKMULTISIGVERIFY = 0xAF,
    OP_CHECKLOCKTIMEVERIFY = 0xB1,

    // expansion
    OP_NOP1 = 0xB0,
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
    OP_NOP3 = 0xB2,
    OP_NOP4 = 0xB3,
    OP_NOP5 = 0xB4,
    OP_NOP6 = 0xB5,
    OP_NOP7 = 0xB6,
    OP_NOP8 = 0xB7,
    OP_NOP9 = 0xB8,
    OP_NOP10 = 0xB9,

    // template matching params
    OP_SMALLINTEGER = 0xFA,
    OP_PUBKEYS = 0xFB,
    OP_PUBKEYHASH = 0xFD,
    OP_PUBKEY = 0xFE,

    OP_INVALIDOPCODE = 0xFF,
};

const char *GetOpName(opcodetype opcode);

inline std::string ValueString(const std::vector<uchar> &vch) {
    if(vch.size() <= 4)
      return(strprintf("%d", CBigNum(vch).getint()));
    else
      return(HexStr(vch));
}

inline std::string StackString(const std::vector<std::vector<uchar> > &vStack) {
    std::string str;
    BOOST_FOREACH(const std::vector<uchar> &vch, vStack) {
        if(!str.empty()) str += " ";
        str += ValueString(vch);
    }
    return(str);
}


/** Serialized script, used inside transaction inputs and outputs */
class CScript : public std::vector<uchar> {
protected:
    CScript &push_int64(int64 n) {
        if((n == -1) || ((n >= 1) && (n <= 16))) {
            push_back(n + (OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return(*this);
    }

    CScript &push_uint64(uint64 n) {
        if((n >= 1) && (n <= 16)) {
            push_back(n + (OP_1 - 1));
        } else {
            CBigNum bn(n);
            *this << bn.getvch();
        }
        return(*this);
    }

public:
    CScript() { }
    CScript(const CScript &b) : std::vector<uchar> (b.begin(), b.end()) { }
    CScript(const_iterator pbegin, const_iterator pend) : std::vector<uchar> (pbegin, pend) { }
#ifndef _MSC_VER
    CScript(const uchar *pbegin, const uchar *pend) : std::vector<uchar>(pbegin, pend) { }
#endif

    CScript &operator+=(const CScript &b) {
        insert(end(), b.begin(), b.end());
        return(*this);
    }

    friend CScript operator+(const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    //explicit CScript(char b) is not portable.  Use 'signed char' or 'unsigned char'.
    explicit CScript(signed char b)    { operator<<(b); }
    explicit CScript(short b)          { operator<<(b); }
    explicit CScript(int b)            { operator<<(b); }
    explicit CScript(long b)           { operator<<(b); }
    explicit CScript(int64 b)          { operator<<(b); }
    explicit CScript(unsigned char b)  { operator<<(b); }
    explicit CScript(unsigned int b)   { operator<<(b); }
    explicit CScript(unsigned short b) { operator<<(b); }
    explicit CScript(unsigned long b)  { operator<<(b); }
    explicit CScript(uint64 b)         { operator<<(b); }

    explicit CScript(opcodetype b)     { operator<<(b); }
    explicit CScript(const uint256 &b) { operator<<(b); }
    explicit CScript(const CBigNum &b) { operator<<(b); }
    explicit CScript(const std::vector<unsigned char> &b) { operator<<(b); }

    //CScript &operator<<(char b) is not portable.  Use 'signed char' or 'unsigned char'.
    CScript &operator<<(signed char b)    { return push_int64(b); }
    CScript &operator<<(short b)          { return push_int64(b); }
    CScript &operator<<(int b)            { return push_int64(b); }
    CScript &operator<<(long b)           { return push_int64(b); }
    CScript &operator<<(int64 b)          { return push_int64(b); }
    CScript &operator<<(unsigned char b)  { return push_uint64(b); }
    CScript &operator<<(unsigned int b)   { return push_uint64(b); }
    CScript &operator<<(unsigned short b) { return push_uint64(b); }
    CScript &operator<<(unsigned long b)  { return push_uint64(b); }
    CScript &operator<<(uint64 b)         { return push_uint64(b); }

    CScript &operator<<(opcodetype opcode) {
        if((opcode < 0) || (opcode > 0xFF))
          throw(std::runtime_error("CScript::operator<<() : invalid opcode"));
        insert(end(), (uchar)opcode);
        return(*this);
    }

    CScript &operator<<(const uint160 &b) {
        insert(end(), sizeof(b));
        insert(end(), (uchar *) &b, (uchar *) &b + sizeof(b));
        return(*this);
    }

    CScript &operator<<(const uint256 &b) {
        insert(end(), sizeof(b));
        insert(end(), (uchar *) &b, (uchar *) &b + sizeof(b));
        return(*this);
    }

    CScript &operator<<(const CPubKey &key) {
        std::vector<uchar> vchKey = key.Raw();
        return (*this) << vchKey;
    }

    CScript &operator<<(const CBigNum &b) {
        *this << b.getvch();
        return(*this);
    }

    CScript &operator<<(const std::vector<uchar> &b) {
        if(b.size() < OP_PUSHDATA1) {
            insert(end(), (uchar)b.size());
        } else if(b.size() <= 0xFF) {
            insert(end(), OP_PUSHDATA1);
            insert(end(), (uchar)b.size());
        } else if(b.size() <= 0xFFFF) {
            insert(end(), OP_PUSHDATA2);
            ushort nSize = b.size();
            insert(end(), (uchar *) &nSize, (uchar *) &nSize + sizeof(nSize));
        } else {
            insert(end(), OP_PUSHDATA4);
            uint nSize = b.size();
            insert(end(), (uchar *) &nSize, (uchar *) &nSize + sizeof(nSize));
        }
        insert(end(), b.begin(), b.end());
        return(*this);
    }

    CScript &operator<<(const CScript &b) {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this member fn
        assert(!"Warning: Pushing a CScript onto a CScript with << is probably not intended, use + to concatenate!");
        return(*this);
    }


    bool GetOp(iterator &pc, opcodetype &opcodeRet, std::vector<uchar> &vchRet) {
         // Wrapper so it can be called with either iterator or const_iterator
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, &vchRet);
         pc = begin() + (pc2 - begin());
         return(fRet);
    }

    bool GetOp(iterator &pc, opcodetype &opcodeRet) {
         const_iterator pc2 = pc;
         bool fRet = GetOp2(pc2, opcodeRet, NULL);
         pc = begin() + (pc2 - begin());
         return(fRet);
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet, std::vector<uchar> &vchRet) const {
        return(GetOp2(pc, opcodeRet, &vchRet));
    }

    bool GetOp(const_iterator &pc, opcodetype &opcodeRet) const {
        return(GetOp2(pc, opcodeRet, NULL));
    }

    bool GetOp2(const_iterator &pc, opcodetype &opcodeRet, std::vector<uchar> *pvchRet) const {
        opcodeRet = OP_INVALIDOPCODE;
        if(pvchRet) pvchRet->clear();
        if(pc >= end()) return(false);

        // Read instruction
        if(end() - pc < 1) return(false);
        uint opcode = *pc++;

        // Immediate operand
        if(opcode <= OP_PUSHDATA4) {
            uint nSize;
            if(opcode < OP_PUSHDATA1) {
                nSize = opcode;
            } else if(opcode == OP_PUSHDATA1) {
                if(end() - pc < 1) return(false);
                nSize = *pc++;
            } else if(opcode == OP_PUSHDATA2) {
                if(end() - pc < 2) return(false);
                nSize = 0;
                memcpy(&nSize, &pc[0], 2);
                pc += 2;
            } else if(opcode == OP_PUSHDATA4) {
                if(end() - pc < 4) return(false);
                memcpy(&nSize, &pc[0], 4);
                pc += 4;
            }
            if(((end() - pc) < 0) || ((uint)(end() - pc) < nSize))
              return(false);
            if(pvchRet)
              pvchRet->assign(pc, pc + nSize);
            pc += nSize;
        }

        opcodeRet = (opcodetype)opcode;
        return(true);
    }

    /* Decode small integers */
    static int DecodeOP_N(opcodetype opcode) {
        if(opcode == OP_0) return(0);
        assert((opcode >= OP_1) && (opcode <= OP_16));
        return((int)opcode - (int)(OP_1 - 1));
    }

    /* Encode small integers */
    static opcodetype EncodeOP_N(int n) {
        assert((n >= 0) && (n <= 16));
        if(!n) return(OP_0);
        return((opcodetype)(OP_1 + n - 1));
    }

    int FindAndDelete(const CScript &b) {
        int nFound = 0;
        if(b.empty()) return(nFound);
        iterator pc = begin();
        opcodetype opcode;
        do {
            while(((end() - pc) >= (long)b.size()) && !memcmp(&pc[0], &b[0], b.size())) {
                erase(pc, pc + b.size());
                ++nFound;
            }
        }
        while(GetOp(pc, opcode));
        return(nFound);
    }

    int Find(opcodetype op) const {
        int nFound = 0;
        opcodetype opcode;
        const_iterator pc;
        for(pc = begin(); (pc != end()) && GetOp(pc, opcode); )
          if(opcode == op) ++nFound;
        return(nFound);
    }

    // Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs
    // as 20 sigops. With pay-to-script-hash, that changed:
    // CHECKMULTISIGs serialized in scriptSigs are
    // counted more accurately, assuming they are of the form
    //  ... OP_N CHECKMULTISIG ...
    uint GetSigOpCount(bool fAccurate) const;

    // Accurately count sigOps, including sigOps in
    // pay-to-script-hash transactions:
    uint GetSigOpCount(const CScript &scriptSig) const;

    bool IsPayToScriptHash() const;

    // Called by CTransaction::IsStandard
    bool IsPushOnly() const {
        const_iterator pc = begin();
        while(pc < end()) {
            opcodetype opcode;
            if(!GetOp(pc, opcode)) return(false);
            if(opcode > OP_16) return(false);
        }
        return(true);
    }

    /* Returns whether the script is guaranteed to fail at execution,
     * regardless of the initial stack. This allows outputs to be pruned
     * instantly when entering the UTXO set. */
    bool IsUnspendable() const {
        return((size() > 0) && (*begin() == OP_RETURN));
    }

    void SetDestination(const CTxDestination &addr);
    void SetMultisig(int nRequired, const std::vector<CKey> &keys);

    void PrintHex() const {
        printf("CScript(%s)\n", HexStr(begin(), end(), true).c_str());
    }

    std::string ToString() const {
        std::string str;
        opcodetype opcode;
        std::vector<uchar> vch;
        const_iterator pc = begin();
        while(pc < end()) {
            if(!str.empty()) str += " ";
            if(!GetOp(pc, opcode, vch)) {
                str += "[error]";
                return(str);
            }
            if((0 <= opcode) && (opcode <= OP_PUSHDATA4))
              str += ValueString(vch);
            else
              str += GetOpName(opcode);
        }
        return(str);
    }

    void print() const {
        printf("%s\n", ToString().c_str());
    }

    CScriptID GetID() const {
        return(CScriptID(Hash160(*this)));
    }
};

CScript GetScriptForPubKeyHash(const CKeyID &keyID);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
class CScriptCompressor {
private:
    // make this static for now (there are only 6 special scripts defined)
    // this can potentially be extended together with a new nVersion for
    // transactions, in which case this value becomes dependent on nVersion
    // and nHeight of the enclosing transaction.
    static const unsigned int nSpecialScripts = 6;

    CScript &script;

protected:
    // These check for scripts for which a special case with a shorter encoding is defined.
    // They are implemented separately from the CScript test, as these test for exact byte
    // sequence correspondences, and are more strict. For example, IsToPubKey also verifies
    // whether the public key is valid (as invalid ones cannot be represented in compressed
    // form).
    bool IsToKeyID(CKeyID &hash) const;
    bool IsToScriptID(CScriptID &hash) const;
    bool IsToPubKey(std::vector<uchar> &pubkey) const;

    bool Compress(std::vector<uchar> &out) const;
    unsigned int GetSpecialSize(uint nSize) const;
    bool Decompress(uint nSize, const std::vector<uchar> &out);

public:
    CScriptCompressor(CScript &scriptIn) : script(scriptIn) { }

    uint GetSerializeSize(int nType, int nVersion) const {
        std::vector<uchar> compr;
        if(Compress(compr)) return(compr.size());
        uint nSize = script.size() + nSpecialScripts;
        return(script.size() + VARINT(nSize).GetSerializeSize(nType, nVersion));
    }

    template<typename Stream>
    void Serialize(Stream &s, int nType, int nVersion) const {
        std::vector<uchar> compr;
        if(Compress(compr)) {
            s << CFlatData(&compr[0], &compr[compr.size()]);
            return;
        }
        uint nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << CFlatData(&script[0], &script[script.size()]);
    }

    template<typename Stream>
    void Unserialize(Stream &s, int nType, int nVersion) {
        uint nSize;
        s >> VARINT(nSize);
        if(nSize < nSpecialScripts) {
            std::vector<uchar> vch(GetSpecialSize(nSize), 0x00);
            s >> REF(CFlatData(&vch[0], &vch[vch.size()]));
            Decompress(nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        script.resize(nSize);
        s >> REF(CFlatData(&script[0], &script[script.size()]));
    }
};

bool IsCanonicalPubKey(const std::vector<uchar> &vchPubKey);
bool IsCanonicalSignature(const std::vector<uchar> &vchSig);

bool EvalScript(std::vector<std::vector<uchar> > &stack, const CScript &script,
  const CTransaction &txTo, uint nIn, uint flags, int nHashType);
bool Solver(const CScript &scriptPubKey, txnouttype &typeRet,
  std::vector<std::vector<uchar> > &vSolutionsRet);
int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<uchar> > &vSolutions);
bool IsStandard(const CScript &scriptPubKey);
isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey);
isminetype IsMine(const CKeyStore &keystore, const CTxDestination &dest);

void ExtractAffectedKeys(const CKeyStore &keystore, const CScript& scriptPubKey,
  std::vector<CKeyID> &vKeys);
bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);
bool ExtractDestinations(const CScript &scriptPubKey, txnouttype &typeRet,
  std::vector<CTxDestination> &addressRet, int &nRequiredRet);
bool SignSignature(const CKeyStore &keystore, const CScript &fromPubKey,
  CTransaction &txTo, uint nIn, int nHashType = SIGHASH_ALL);
bool SignSignature(const CKeyStore &keystore, const CTransaction &txFrom,
  CTransaction &txTo, uint nIn, int nHashType = SIGHASH_ALL);
bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey,
  const CTransaction &txTo, uint nIn, uint flags, int nHashType);
bool VerifySignature(const CCoins &txFrom, const CTransaction &txTo,
  uint nIn, uint flags, int nHashType);

// Given two sets of signatures for scriptPubKey, possibly with OP_0 placeholders,
// combine them intelligently and return the result.
CScript CombineSignatures(CScript scriptPubKey, const CTransaction &txTo,
 uint nIn, const CScript &scriptSig1, const CScript &scriptSig2);

#endif /* SCRIPT_H */
