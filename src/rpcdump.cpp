// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <fstream>

#include "init.h" // for pwalletMain
#include "rpc.h"
#include "ui_interface.h"
#include "base58.h"

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3))
      throw(runtime_error(
        "importprivkey <orbitcoin_privkey> [label] [rescan]\n"
        "Adds a private key (as returned by dumpprivkey) to your wallet.\n"
        "Block chain re-scanning is on (true) by default."));

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    bool fRescan = true;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CCoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        pwalletMain->UpdateTimeFirstKey();

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value importaddress(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3)) {
        string msg =  "importaddress <address> [label] [rescan]\n"
        "Adds a watch only (unspendable) P2PKH address to your wallet.\n"
        "Pubkey hash or script in hex may be specified instead of the address.\n"
        "Block chain re-scanning is off (false) by default.\n";
        throw(runtime_error(msg));
    }

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr;

    if(IsHex(params[0].get_str())) {
        std::vector<uchar> vchScriptPubKey(ParseHex(params[0].get_str()));
        std::string strTemp;
        if(vchScriptPubKey.size() == 20) {
            /* 20-byte pubkey hash assumed;
             * <pubKeyHash> = RIPEMD160(SHA256(pubKey))
             * Example using OpenSSL:
             * echo -n <pubKey> | xxd -r -p | openssl dgst -sha256 -binary | openssl dgst -rmd160
             * Convert to 25-byte script:
             * OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG */
            strTemp = std::string(vchScriptPubKey.begin(), vchScriptPubKey.end());
            const uchar begin[] = { 0x76, 0xA9, 0x14 };
            const uchar end[] = { 0x88, 0xAC };
            vchScriptPubKey.insert(vchScriptPubKey.begin(), begin, begin + 3);
            vchScriptPubKey.insert(vchScriptPubKey.end(), end, end + 2);
        } else if(vchScriptPubKey.size() == 25) {
            /* Copy the public key hash */
            strTemp = params[0].get_str().substr(6, 40);
        } else {
            throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid pubkey hash or script"));
        }
        script = CScript(vchScriptPubKey.begin(), vchScriptPubKey.end());
        /* Insert the Base58 prefix */
        char prefix[2];
        if(fTestNet) prefix[0] = PUBKEY_ADDRESS_TEST_PREFIX;
        else prefix[0] = PUBKEY_ADDRESS_PREFIX;
        prefix[1] = 0x00;
        strTemp.insert(0, prefix);
        /* Convert and encode */
        std::vector<uchar> vchTemp(ParseHex(strTemp));
        addr = CCoinAddress(EncodeBase58Check(vchTemp));
    } else {
        CKeyID keyID;
        addr = CCoinAddress(params[0].get_str());
        if(!addr.GetKeyID(keyID))
          throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address"));
        script = GetScriptForPubKeyHash(keyID);
    }

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The address is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the address to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}

Value importpubkey(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 1) || (params.size() > 3))
      throw(runtime_error(
        "importpubkey <public key> [label] [rescan]\n"
        "Adds a watch only (unspendable) public key in hex to your wallet.\n"
        "Block chain re-scanning is off (false) by default.\n"));

    string strLabel = "";
    if(params.size() > 1)
      strLabel = params[1].get_str();

    bool fRescan = false;
    if(params.size() > 2)
      fRescan = params[2].get_bool();

    CScript script;
    CCoinAddress addr(params[0].get_str());

    if(!IsHex(params[0].get_str()))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Hex string expected for public key"));

    CPubKey pubKey(std::vector<uchar> (ParseHex(params[0].get_str())));
    if(!pubKey.IsValid())
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid public key"));

    CKeyID keyID = pubKey.GetID();
    addr = CCoinAddress(keyID);
    script = GetScriptForPubKeyHash(keyID);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if(::IsMine(*pwalletMain, script) == MINE_SPENDABLE)
          throw(JSONRPCError(RPC_WALLET_ERROR, "The private key is already in the wallet"));

        if(pwalletMain->HaveWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "The public key is being watched already"));

        pwalletMain->MarkDirty();

        if(addr.IsValid())
          pwalletMain->SetAddressBookName(addr.Get(), strLabel);

        if(!pwalletMain->AddWatchOnly(script))
          throw(JSONRPCError(RPC_WALLET_ERROR, "Failed to add the public key to the wallet"));

        if(fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }

    }

    return(Value::null);
}

Value importwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet <filename>\n"
            "Imports keys from a wallet dump file (see dumpwallet).");

    EnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str());
    if(!file.is_open())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open a file with wallet keys"));

    if(!ImportWallet(pwalletMain, params[0].get_str().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while importing keys to the wallet"));

    return(Value::null);
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <orbitcoin_address>\n"
            "Reveals the private key corresponding to <orbitcoin_address>.");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CCoinAddress address;
    if(!address.SetString(strAddress))
      throw(JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Orbitcoin address"));

    CKeyID keyID;
    if(!address.GetKeyID(keyID))
      throw(JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key"));

    CSecret vchSecret;
    bool fCompressed;
    if(!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw(JSONRPCError(RPC_WALLET_ERROR, "Private key for address " +
          strAddress + " is not known"));
    }

    return(CCoinSecret(vchSecret, fCompressed).ToString());
}

Value dumpwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet <filename>\n"
            "Dumps all wallet keys in a human-readable format.");

    EnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if(!file.is_open())
      throw(JSONRPCError(RPC_INVALID_PARAMETER, "Cannot create a file for wallet keys"));

    if(!ExportWallet(pwalletMain, params[0].get_str().c_str()))
      throw(JSONRPCError(RPC_WALLET_ERROR, "Failed while exporting keys from the wallet"));

    return(Value::null);
}
