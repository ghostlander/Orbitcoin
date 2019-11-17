#include "walletmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"

#include "ui_interface.h"
#include "wallet.h"
#include "walletdb.h" // for cloneWallet
#include "base58.h"

#include <QSet>
#include <QTimer>

WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(0),
    transactionTableModel(0),
    cachedBalance(0), cachedUnconfirmed(0), cachedStake(0), cachedImmature(0),
    cachedNumTransactions(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    addressTableModel = new AddressTableModel(wallet, this);
    transactionTableModel = new TransactionTableModel(wallet, this);

    /* This timer runs repeatedly while unconfirmed/immature balance is non-zero */
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

qint64 WalletModel::getBalance(const CCoinControl *coinControl) {

    if(coinControl) {
        int64 nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput &out, vCoins)
          nBalance += out.tx->vout[out.i].nValue;   

        return(nBalance);
    }

    /* Available (confirmed) balance */
    return(wallet->GetBalance(0x1));
}

qint64 WalletModel::getUnconfirmed() {
    /* Unconfirmed balance (mined rewards excluded) */
    return(wallet->GetBalance(0x2));
}

qint64 WalletModel::getStake() {
    /* Immature PoS debit */
    return(wallet->GetMinted(0xE));
}

qint64 WalletModel::getImmature() {
    /* Immature PoW and PoS rewards */
    return(wallet->GetMinted(0x7));
}

int WalletModel::getNumTransactions() const {
    int numTransactions = 0;

    {
        LOCK(wallet->cs_wallet);

        /* The size of mapWallet contains the number of unique transaction IDs
         * (e.g. payments to yourself generate 2 transactions,
         * but both share the same transaction ID) */
        numTransactions = wallet->mapWallet.size();
    }

    return(numTransactions);
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        emit encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    if(nBestHeight != cachedNumBlocks)
    {
        // Balance and number of transactions might have changed
        cachedNumBlocks = nBestHeight;
        checkBalanceChanged();
    }
}

void WalletModel::checkBalanceChanged() {
    qint64 newBalance     = getBalance();
    qint64 newStake       = getStake();
    qint64 newUnconfirmed = getUnconfirmed();
    qint64 newImmature    = getImmature();

    if((cachedBalance != newBalance) || (cachedStake != newStake) ||
      (cachedUnconfirmed != newUnconfirmed) || (cachedImmature != newImmature)) {
        cachedBalance     = newBalance;
        cachedStake       = newStake;
        cachedUnconfirmed = newUnconfirmed;
        cachedImmature    = newImmature;
        emit(balanceChanged(newBalance, newStake, newUnconfirmed, newImmature));
    }
}

void WalletModel::updateTransaction(const QString &hash, int status)
{
    if(transactionTableModel)
        transactionTableModel->updateTransaction(hash, status);

    // Balance and number of transactions might have changed
    checkBalanceChanged();

    int newNumTransactions = getNumTransactions();
    if(cachedNumTransactions != newNumTransactions)
    {
        cachedNumTransactions = newNumTransactions;
        emit numTransactionsChanged(newNumTransactions);
    }
}

void WalletModel::updateAddressBook(const QString &address, const QString &label, bool isMine, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, status);
}

bool WalletModel::validateAddress(const QString &address) {
    CCoinAddress addressParsed(address.toStdString());
    return(addressParsed.IsValid());
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction,
   const QString &txcomment, const CCoinControl *coinControl) {
    qint64 total = 0;
    std::vector<std::pair<CScript, int64> > vecSend;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();

    if(recipients.empty()) return(OK);

    /* Used to detect duplicates */
    QSet<QString> setAddress;
    int nAddresses = 0;

    // Pre-check input data for validity
    foreach(const SendCoinsRecipient &rcp, recipients) {
        if(!validateAddress(rcp.address)) return(InvalidAddress);

        if(rcp.amount <= 0) return(InvalidAmount);

        setAddress.insert(rcp.address);
        ++nAddresses;

        CScript scriptPubKey;
        scriptPubKey.SetDestination(CCoinAddress(rcp.address.toStdString()).Get());
        vecSend.push_back(std::pair<CScript, int64>(scriptPubKey, rcp.amount));

        total += rcp.amount;
    }

    if(setAddress.size() != nAddresses) return(DuplicateAddress);

    int64 nBalance = getBalance(coinControl);
    if(total > nBalance) return(AmountExceedsBalance);

    if((total + nTransactionFee) > nBalance) {
        transaction.setTransactionFee(nTransactionFee);
        return(SendCoinsReturn(AmountWithFeeExceedsBalance));
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        transaction.newPossibleKeyChange(wallet);
        int64 nFeeRequired = 0;

        CWalletTx *newTx = transaction.getTransaction();
        CReserveKey *keyChange = transaction.getPossibleKeyChange();
	std::string strTxComment = txcomment.toStdString();
	if(!strTxComment.empty()) strTxComment = "text:" + strTxComment;
        bool fCreated = wallet->CreateTransaction(vecSend, *newTx, *keyChange,
          nFeeRequired, strTxComment, coinControl);
        transaction.setTransactionFee(nFeeRequired);

        if(!fCreated) {
            if((total + nFeeRequired) > nBalance)
              return(SendCoinsReturn(AmountWithFeeExceedsBalance));
            return(TransactionCreationFailed);
        }
    }

    return(SendCoinsReturn(OK));
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction) {
    /* Store serialised transaction */
    QByteArray transaction_array;

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        if(!wallet->CommitTransaction(*newTx, *keyChange))
          return(TransactionCommitFailed);

        CTransaction *t = (CTransaction *) newTx;
        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *t;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    /* Add addresses / update labels that we've sent to the address book */
    foreach(const SendCoinsRecipient &rcp, transaction.getRecipients()) {
        std::string strAddress = rcp.address.toStdString();
        CTxDestination dest = CCoinAddress(strAddress).Get();
        std::string strLabel = rcp.label.toStdString();

        {
            LOCK(wallet->cs_wallet);

            std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(dest);

            /* Check if we have a new address or an updated label */
            if((mi == wallet->mapAddressBook.end()) || (mi->second != strLabel))
              wallet->SetAddressBookName(dest, strLabel);
        }
    }

    return(SendCoinsReturn(OK));
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const {

    if(!wallet->IsCrypted())
      return(Unencrypted);

    if(wallet->IsLocked())
      return(Locked);

    if(fStakingOnly)
      return(UnlockedStaking);
    else
      return(Unlocked);
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::cloneWallet(const QString &filename) {
    return(BackupWallet(*wallet, filename.toLocal8Bit().data()));
}

bool WalletModel::exportWallet(const QString &filename) {
    return(ExportWallet(wallet, filename.toLocal8Bit().data()));
}

bool WalletModel::importWallet(const QString &filename) {
    return(ImportWallet(wallet, filename.toLocal8Bit().data()));
}

void WalletModel::getStakeWeightQuick(const int64& nTime, const int64& nValue, uint64& nWeight) {
   wallet->GetStakeWeightQuick(nTime, nValue, nWeight);
}

void WalletModel::getStakeWeight(uint64& nMinWeightInputs, uint64& nAvgWeightInputs, uint64& nMaxWeightInputs, uint64& nTotalStakeWeight) {
   wallet->GetStakeWeight(*wallet, nMinWeightInputs, nAvgWeightInputs, nMaxWeightInputs, nTotalStakeWeight);
}

void WalletModel::repairWallet(int& nMismatchSpent, int& nOrphansFound, int64& nBalanceInQuestion, bool fCheckOnly) {
    wallet->FixSpentCoins(nMismatchSpent, nOrphansFound, nBalanceInQuestion, fCheckOnly);
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    OutputDebugStringF("NotifyKeyStoreStatusChanged\n");
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet,
  const CTxDestination &address, const std::string &label, bool isMine, ChangeType status) {
    OutputDebugStringF("NotifyAddressBookChanged %s %s isMine=%i status=%i\n",
      CCoinAddress(address).ToString().c_str(), label.c_str(), isMine, status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
      Q_ARG(QString, QString::fromStdString(CCoinAddress(address).ToString())),
      Q_ARG(QString, QString::fromStdString(label)),
      Q_ARG(bool, isMine), Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    OutputDebugStringF("NotifyTransactionChanged %s status=%i\n", hash.GetHex().c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;

    if((!was_locked) && fStakingOnly) {
       setWalletLocked(true);
       was_locked = getEncryptionStatus() == Locked;
    }

    if(was_locked)
    {
        // Request UI to unlock wallet
        emit requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return(UnlockContext(this, valid, was_locked && !fStakingOnly));
}

WalletModel::UnlockContext::UnlockContext(WalletModel *wallet, bool valid, bool relock):
        wallet(wallet),
        valid(valid),
        relock(relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const {
    return(wallet->GetPubKey(address, vchPubKeyOut));
}

/* Returns a list of COutputs from COutPoints */
void WalletModel::getOutputs(const std::vector<COutPoint> &vOutpoints,
  std::vector<COutput> &vOutputs) {

    BOOST_FOREACH(const COutPoint &outpoint, vOutpoints) {
        if(!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if(nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        vOutputs.push_back(out);
    }
}

/* AvailableCoins + LockedCoins grouped by a wallet address,
 * put change in one group with the wallet address */
void WalletModel::listCoins(std::map<QString, std::vector<COutput> > &mapCoins) const {
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);

    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);

    /* Add locked coins */
    BOOST_FOREACH(const COutPoint &outpoint, vLockedCoins) {
        if(!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if(nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true);
        vCoins.push_back(out);
    }

    BOOST_FOREACH(const COutput &out, vCoins) {
        COutput cout = out;

        while(wallet->IsChange(cout.tx->vout[cout.i]) &&
          (cout.tx->vin.size() > 0) && wallet->IsMine(cout.tx->vin[0])) {
            if(!wallet->mapWallet.count(cout.tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->vin[0].prevout.hash],
              cout.tx->vin[0].prevout.n, 0, true);
        }

        CTxDestination address;
        if(!ExtractDestination(cout.tx->vout[cout.i].scriptPubKey, address)) continue;
        mapCoins[CCoinAddress(address).ToString().c_str()].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, uint n) const {
    return(wallet->IsLockedCoin(hash, n));
}

void WalletModel::lockCoin(COutPoint &output) {
    wallet->LockCoin(output);
}

void WalletModel::unlockCoin(COutPoint &output) {
    wallet->UnlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint> &vOutpts) {
    wallet->ListLockedCoins(vOutpts);
}
