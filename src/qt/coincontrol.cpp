/*
 * Copyright (c) 2013 Cozz Lovan <cozzlovan@yahoo.com>
 * Copyright (c) 2014-2019 John Doering <ghostlander@orbitcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "coincontrol.h"
#include "ui_coincontrol.h"

#include "init.h"
#include "coinunits.h"
#include "walletmodel.h"
#include "addresstablemodel.h"
#include "optionsmodel.h"
#include "guiutil.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QColor>
#include <QCursor>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFlags>
#include <QIcon>
#include <QString>
#include <QTreeWidget>
#include <QTreeWidgetItem>

using namespace std;

QList<qint64> CoinControl::payAmounts;
CCoinControl *CoinControl::control = new CCoinControl();

CoinControl::CoinControl(QWidget *parent) :
  QDialog(parent), ui(new Ui::CoinControl), model(0) {

    ui->setupUi(this);

    QAction *copyAddressAction = new QAction(tr("Copy address"), this);
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);
    copyTransactionHashAction = new QAction(tr("Copy payment ID"), this);

    contextMenu = new QMenu();
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyTransactionHashAction);

    connect(ui->treeWidget, SIGNAL(customContextMenuRequested(QPoint)),
      this, SLOT(showMenu(QPoint)));
    connect(copyAddressAction, SIGNAL(triggered()),
      this, SLOT(copyAddress()));
    connect(copyLabelAction, SIGNAL(triggered()),
      this, SLOT(copyLabel()));
    connect(copyAmountAction, SIGNAL(triggered()),
      this, SLOT(copyAmount()));
    connect(copyTransactionHashAction, SIGNAL(triggered()),
      this, SLOT(copyTransactionHash()));

    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardNetAmountAction = new QAction(tr("Copy net amount"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardPriorityAction = new QAction(tr("Copy priority"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy low output"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);

    connect(clipboardQuantityAction, SIGNAL(triggered()),
      this, SLOT(clipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()),
      this, SLOT(clipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()),
      this, SLOT(clipboardFee()));
    connect(clipboardNetAmountAction, SIGNAL(triggered()),
      this, SLOT(clipboardNetAmount()));
    connect(clipboardBytesAction, SIGNAL(triggered()),
      this, SLOT(clipboardBytes()));
    connect(clipboardPriorityAction, SIGNAL(triggered()),
      this, SLOT(clipboardPriority()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()),
      this, SLOT(clipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()),
      this, SLOT(clipboardChange()));

    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlNetAmount->addAction(clipboardNetAmountAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlPriority->addAction(clipboardPriorityAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    /* Toggle tree/list mode */
    connect(ui->radioTreeMode, SIGNAL(toggled(bool)),
      this, SLOT(radioTreeMode(bool)));
    connect(ui->radioListMode, SIGNAL(toggled(bool)),
      this, SLOT(radioListMode(bool)));

    /* Click on checkbox */
    connect(ui->treeWidget, SIGNAL(itemChanged(QTreeWidgetItem *, int)),
      this, SLOT(viewItemChanged(QTreeWidgetItem *, int)));

    /* Click on header */
#if (QT_VERSION < 0x050000)
    ui->treeWidget->header()->setClickable(true);
#else
    ui->treeWidget->header()->setSectionsClickable(true);
#endif
    connect(ui->treeWidget->header(), SIGNAL(sectionClicked(int)),
      this, SLOT(headerSectionClicked(int)));

    /* OK button */
    connect(ui->buttonBox, SIGNAL(clicked(QAbstractButton *)),
      this, SLOT(buttonBoxClicked(QAbstractButton *)));

    /* (un)select all */
    connect(ui->pushButtonSelectAll, SIGNAL(clicked()),
      this, SLOT(buttonSelectAllClicked()));

    ui->treeWidget->setColumnWidth(COLUMN_CHECKBOX, 90);
    ui->treeWidget->setColumnWidth(COLUMN_AMOUNT, 100);
    ui->treeWidget->setColumnWidth(COLUMN_LABEL, 100);
    ui->treeWidget->setColumnWidth(COLUMN_ADDRESS, 280);
    ui->treeWidget->setColumnWidth(COLUMN_DATE, 110);
    ui->treeWidget->setColumnWidth(COLUMN_CONFIRMATIONS, 100);
    ui->treeWidget->setColumnWidth(COLUMN_PRIORITY, 90);
    ui->treeWidget->setColumnWidth(COLUMN_WEIGHT, 80);
    /* Store transacton hash in this column, but don't show it */
    ui->treeWidget->setColumnHidden(COLUMN_TXHASH, true);
    /* Store vout index in this column, but don't show it */
    ui->treeWidget->setColumnHidden(COLUMN_VOUT_INDEX, true);
    /* Store amount in this column, but don't show it */
    ui->treeWidget->setColumnHidden(COLUMN_AMOUNT_INT64, true);
    /* Store priority int64 in this column, but don't show it */
    ui->treeWidget->setColumnHidden(COLUMN_PRIORITY_INT64, true);

    /* The default view order is descending by amount */
    sortView(COLUMN_AMOUNT_INT64, Qt::DescendingOrder);
}

CoinControl::~CoinControl() {
    delete(ui);
}

void CoinControl::setModel(WalletModel *model) {

    this->model = model;

    if(model && model->getOptionsModel() && model->getAddressTableModel()) {
        updateView();
        CoinControl::updateLabels(model, this);
    }
}

QString CoinControl::strPad(QString s, int nPadLength, QString sPadding) {
    while(s.length() < nPadLength) s = sPadding + s;
    return(s);
}

/* OK button */
void CoinControl::buttonBoxClicked(QAbstractButton *button) {
    if(ui->buttonBox->buttonRole(button) == QDialogButtonBox::AcceptRole)
      done(QDialog::Accepted);
}

/* (un)select all */
void CoinControl::buttonSelectAllClicked() {
    int i;

    Qt::CheckState state = Qt::Checked;
    for(i = 0; i < ui->treeWidget->topLevelItemCount(); i++) {
        if(ui->treeWidget->topLevelItem(i)->checkState(COLUMN_CHECKBOX) != Qt::Unchecked) {
            state = Qt::Unchecked;
            break;
        }
    }
    ui->treeWidget->setEnabled(false);
    for(i = 0; i < ui->treeWidget->topLevelItemCount(); i++) {
        if(ui->treeWidget->topLevelItem(i)->checkState(COLUMN_CHECKBOX) != state)
          ui->treeWidget->topLevelItem(i)->setCheckState(COLUMN_CHECKBOX, state);
    }
    ui->treeWidget->setEnabled(true);
    CoinControl::updateLabels(model, this);
}

/* Context menu */
void CoinControl::showMenu(const QPoint &point) {
    QTreeWidgetItem *item = ui->treeWidget->itemAt(point);

    if(item) {
        contextMenuItem = item;

        /* Disable some items like copy payment ID for tree roots in the context menu */
        if(item->text(COLUMN_TXHASH).length() == 64) {
            /* Transaction hash is 64 characters what means it's a child node,
             * not a parent node in tree mode */
            copyTransactionHashAction->setEnabled(true);
        } else {
            /* Click on parent node in tree mode -> disable all */
            copyTransactionHashAction->setEnabled(false);
        }

        /* Show context menu */
        contextMenu->exec(QCursor::pos());
    }
}

/* Context menu action: copy amount */
void CoinControl::copyAmount() {
    GUIUtil::setClipboard(contextMenuItem->text(COLUMN_AMOUNT));
}

/* Context menu action: copy label */
void CoinControl::copyLabel() {
    if(ui->radioTreeMode->isChecked() &&
      !contextMenuItem->text(COLUMN_LABEL).length() && contextMenuItem->parent()) {
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_LABEL));
    } else {
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_LABEL));
    }
}

/* Context menu action: copy address */
void CoinControl::copyAddress() {
    if(ui->radioTreeMode->isChecked() &&
      !contextMenuItem->text(COLUMN_ADDRESS).length() && contextMenuItem->parent()) {
        GUIUtil::setClipboard(contextMenuItem->parent()->text(COLUMN_ADDRESS));
    } else {
        GUIUtil::setClipboard(contextMenuItem->text(COLUMN_ADDRESS));
    }
}

/* Context menu action: copy payment ID */
void CoinControl::copyTransactionHash() {
    GUIUtil::setClipboard(contextMenuItem->text(COLUMN_TXHASH));
}

/* Copy label "Quantity" to clipboard */
void CoinControl::clipboardQuantity() {
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

/* Copy label "Amount" to clipboard */
void CoinControl::clipboardAmount() {
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text() \
      .left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

/* Copy label "Fee" to clipboard */
void CoinControl::clipboardFee() {
    GUIUtil::setClipboard(ui->labelCoinControlFee->text() \
      .left(ui->labelCoinControlFee->text().indexOf(" ")));
}

/* Copy label "Net amount" to clipboard */
void CoinControl::clipboardNetAmount() {
    GUIUtil::setClipboard(ui->labelCoinControlNetAmount->text() \
      .left(ui->labelCoinControlNetAmount->text().indexOf(" ")));
}

/* Copy label "Bytes" to clipboard */
void CoinControl::clipboardBytes() {
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text());
}

/* Copy label "Priority" to clipboard */
void CoinControl::clipboardPriority() {
    GUIUtil::setClipboard(ui->labelCoinControlPriority->text());
}

/* Copy label "Low output" to clipboard */
void CoinControl::clipboardLowOutput() {
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

/* Copy label "Change" to clipboard */
void CoinControl::clipboardChange() {
    GUIUtil::setClipboard(ui->labelCoinControlChange->text() \
      .left(ui->labelCoinControlChange->text().indexOf(" ")));
}

/* Tree view: sort */
void CoinControl::sortView(int column, Qt::SortOrder order) {
    sortColumn = column;
    sortOrder = order;
    ui->treeWidget->sortItems(column, order);
    ui->treeWidget->header()->setSortIndicator(
      (sortColumn == COLUMN_AMOUNT_INT64 ? COLUMN_AMOUNT :
      (sortColumn == COLUMN_PRIORITY_INT64 ? COLUMN_PRIORITY : sortColumn)), sortOrder);
}

/* Tree view: header clicked */
void CoinControl::headerSectionClicked(int logicalIndex) {

    if(logicalIndex == COLUMN_CHECKBOX) {
        /* Click on the leftmost column, do nothing */
        ui->treeWidget->header()->setSortIndicator(
          (sortColumn == COLUMN_AMOUNT_INT64 ? COLUMN_AMOUNT :
          (sortColumn == COLUMN_PRIORITY_INT64 ? COLUMN_PRIORITY : sortColumn)), sortOrder);
    } else {
        /* Sort by amount */
        if(logicalIndex == COLUMN_AMOUNT)
          logicalIndex = COLUMN_AMOUNT_INT64;

        /* Sort by priority */
        if(logicalIndex == COLUMN_PRIORITY)
          logicalIndex = COLUMN_PRIORITY_INT64;

        if(sortColumn == logicalIndex) {
            sortOrder =
              ((sortOrder == Qt::AscendingOrder) ? Qt::DescendingOrder : Qt::AscendingOrder);
        } else {
            sortColumn = logicalIndex;
            /* Descending order for amount, priority, date, confirmations,
             * ascending otherwise */
            sortOrder = ((sortColumn == COLUMN_AMOUNT_INT64) ||
              (sortColumn == COLUMN_PRIORITY_INT64) ||
              (sortColumn == COLUMN_DATE) ||
              (sortColumn == COLUMN_CONFIRMATIONS) ||
              (sortColumn == COLUMN_WEIGHT) ?
              Qt::DescendingOrder : Qt::AscendingOrder);
        }

        sortView(sortColumn, sortOrder);
    }
}

/* Toggle tree mode */
void CoinControl::radioTreeMode(bool checked) {
    if(checked && model) updateView();
}

/* Toggle list mode */
void CoinControl::radioListMode(bool checked) {
    if(checked && model) updateView();
}

/* Checkbox clicked */
void CoinControl::viewItemChanged(QTreeWidgetItem *item, int column) {

    if((column == COLUMN_CHECKBOX) && (item->text(COLUMN_TXHASH).length() == 64)) {
        /* Transaction hash is 64 characters what means it's a child node,
         * not a parent node in tree mode */
        COutPoint outpt(uint256(item->text(COLUMN_TXHASH).toStdString()),
          item->text(COLUMN_VOUT_INDEX).toUInt());

        if(item->checkState(COLUMN_CHECKBOX) == Qt::Unchecked) {
            control->UnSelect(outpt);
        } else if(item->isDisabled()) {
            /* Locked which happens if "check all" through parent node */
            item->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);
        } else {
            control->Select(outpt);
        }

        /* Selection changed, update labels */
        if(ui->treeWidget->isEnabled())
          CoinControl::updateLabels(model, this);
    }
}

QString CoinControl::getPriorityLabel(double dPriority) {
    CTransaction tx;

    if(tx.AllowFree(dPriority)) {
        if     (tx.AllowFree(dPriority / 1000000))  return(tr("highest"));
        else if(tx.AllowFree(dPriority / 100000))   return(tr("higher"));
        else if(tx.AllowFree(dPriority / 10000))    return(tr("high"));
        else if(tx.AllowFree(dPriority / 1000))     return(tr("above medium"));
        else                                        return(tr("medium"));
    } else {
        if     (tx.AllowFree(dPriority * 10))       return(tr("below medium"));
        else if(tx.AllowFree(dPriority * 100))      return(tr("low"));
        else if(tx.AllowFree(dPriority * 1000))     return(tr("lower"));
        else                                        return(tr("lowest"));
    }
}

void CoinControl::updateLabels(WalletModel *model, QDialog *dialog) {
    CTransaction tx;

    if(!model) return;

    /* Amount to pay */
    qint64 nPayAmount = 0;
    bool fLowOutput = false, fDustOutput = false, fDustChange = false;

    foreach(const qint64 &amount, CoinControl::payAmounts) {
        nPayAmount += amount;

        if(amount > 0) {
            if(amount < MIN_TX_FEE) fLowOutput  = true;
            if(amount < TX_DUST)    fDustOutput = true;
        }
    }

    QString sPriorityLabel = "";
    int64 nAmount = 0, nPayFee = 0, nNetAmount = 0, nChange = 0;
    uint nBytes  = 0, nBytesInputs = 0, nQuantity = 0;
    int nQuantityUncompressed  = 0;
    double dPriority = 0.0, dPriorityInputs = 0.0;

    vector<COutPoint> vCoinControl;
    vector<COutput> vOutputs;
    control->ListSelected(vCoinControl);
    model->getOutputs(vCoinControl, vOutputs);

    BOOST_FOREACH(const COutput &out, vOutputs) {

        /* Unselect outputs spent already */
        if(out.tx->IsSpent(out.i)) {
            uint256 txhash = out.tx->GetHash();
            COutPoint outpt(txhash, out.i);
            control->UnSelect(outpt);
            continue;
        }

        /* Quantity */
        nQuantity++;

        /* Amount */
        nAmount += out.tx->vout[out.i].nValue;

        /* Priority */
        dPriorityInputs += (double)out.tx->vout[out.i].nValue * (out.nDepth + 1);

        /* Size */
        CTxDestination address;
        if(ExtractDestination(out.tx->vout[out.i].scriptPubKey, address)) {
            CPubKey pubkey;
            CKeyID *keyid = boost::get<CKeyID>(&address);
            if(keyid && model->getPubKey(*keyid, pubkey)) {
                nBytesInputs += (pubkey.IsCompressed() ? 148 : 180);
                if(!pubkey.IsCompressed()) nQuantityUncompressed++;
            } else nBytesInputs += 148;
        } else nBytesInputs += 148;
    }

    /* Calculation */
    if(nQuantity > 0) {

        /* Size; always assume +1 output for the change */
        nBytes = nBytesInputs + ((CoinControl::payAmounts.size() > 0 ?
          CoinControl::payAmounts.size() + 1 : 2) * 34) + 10;

        /* Priority; 29 = 180 - 151 (uncompressed public keys are over the limit) */
        dPriority = dPriorityInputs / (nBytes - nBytesInputs + (nQuantityUncompressed * 29));
        sPriorityLabel = CoinControl::getPriorityLabel(dPriority);

        /* Optional fee */
        int64 nFee = nTransactionFee * (1 + (int64)nBytes / 1000);

        /* Mandatory fee */
        int64 nMinFee = tx.GetMinFee(nBytes, tx.AllowFree(dPriority), GMF_SEND);

        nPayFee = max(nFee, nMinFee);

        if(nPayAmount > 0) {

            if(nPayAmount > nAmount) nPayAmount = nAmount;
            nChange = nAmount - nPayFee - nPayAmount;

            /* To avoid dust outputs, any change < TX_DUST is moved to the fees */
            if(nChange && (nChange < TX_DUST)) {
                nPayFee += nChange;
                nChange = 0;
                fDustChange = true;
            }

            if(!nChange) nBytes -= 34;

        }

        nNetAmount = nAmount - nPayFee;
    }

    /* Update labels */
    int nDisplayUnit = CoinUnits::ORB;
    if(model->getOptionsModel())
      nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    QLabel *l1 = dialog->findChild<QLabel *>("labelCoinControlQuantity");
    QLabel *l2 = dialog->findChild<QLabel *>("labelCoinControlAmount");
    QLabel *l3 = dialog->findChild<QLabel *>("labelCoinControlFee");
    QLabel *l4 = dialog->findChild<QLabel *>("labelCoinControlNetAmount");
    QLabel *l5 = dialog->findChild<QLabel *>("labelCoinControlBytes");
    QLabel *l6 = dialog->findChild<QLabel *>("labelCoinControlPriority");
    QLabel *l7 = dialog->findChild<QLabel *>("labelCoinControlLowOutput");
    QLabel *l8 = dialog->findChild<QLabel *>("labelCoinControlChange");

    /* Enable or disable "low output" and "change" */
    dialog->findChild<QLabel *>("labelCoinControlLowOutputText")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel *>("labelCoinControlLowOutput")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel *>("labelCoinControlChangeText")->setEnabled(nPayAmount > 0);
    dialog->findChild<QLabel *>("labelCoinControlChange")->setEnabled(nPayAmount > 0);

    /* Display the statistics */
    l1->setText(QString::number(nQuantity));                           /* Quantity */
    l2->setText(CoinUnits::formatWithUnit(nDisplayUnit, nAmount));     /* Amount */
    l3->setText(CoinUnits::formatWithUnit(nDisplayUnit, nPayFee));     /* Fee */
    l4->setText(CoinUnits::formatWithUnit(nDisplayUnit, nNetAmount));  /* Net amount */
    l5->setText(((nBytes > 0) ? "~" : "") + QString::number(nBytes));  /* Size */
    l6->setText(sPriorityLabel);                                       /* Priority */
    l7->setText((fLowOutput ?
      (fDustOutput ? tr("dust!") : tr("yes")) : tr("no")));            /* Low output / Dust */
    l8->setText(CoinUnits::formatWithUnit(nDisplayUnit, nChange));     /* Change */

    /* Colour some labels red */
    l5->setStyleSheet((nBytes >= 2000) ? "color:red;" : "");           /* Oversized payment */
    l6->setStyleSheet((!tx.AllowFree(dPriority)) ? "color:red;" : ""); /* Low priority */
    l7->setStyleSheet((fLowOutput) ? "color:red;" : "");               /* Low output */
    l8->setStyleSheet((fDustChange) ? "color:red;" : "");              /* Dust change */

    /* Set up the tool tips */
    l5->setToolTip(tr("Payments over 2000 bytes in size are considered large and require a fee.\n"
      "\n This label turns red if a fee of at least %1 per 1000 bytes is required.") \
      .arg(CoinUnits::formatWithUnit(nDisplayUnit, MIN_TX_FEE)));
    l6->setToolTip(tr("Blocks are filled with payments according to their priority.\n"
      "\n This label turns red if the payment's priority is below \"medium\".\n"
      "\n It means a fee of at least %1 per 1000 bytes is required.") \
      .arg(CoinUnits::formatWithUnit(nDisplayUnit, MIN_TX_FEE)));
    l7->setToolTip(tr("Low value outputs may be unspendable later due to high fees.\n"
       "\n This label turns red if any output is less than %1 in value.\n"
       "\n Amounts below %2 are displayed as dust.") \
       .arg(CoinUnits::formatWithUnit(nDisplayUnit, MIN_TX_FEE)) \
       .arg(CoinUnits::formatWithUnit(nDisplayUnit, TX_DUST)));
    l8->setToolTip(tr("Very low value outputs are considered useless due to high fees.\n"
      "\n This label turns red if the change is less than %1 in value.\n"
      "\n It will be moved to the fees.\n") \
      .arg(CoinUnits::formatWithUnit(nDisplayUnit, TX_DUST)));
    dialog->findChild<QLabel *>("labelCoinControlBytesText")->setToolTip(l5->toolTip());
    dialog->findChild<QLabel *>("labelCoinControlPriorityText")->setToolTip(l6->toolTip());
    dialog->findChild<QLabel *>("labelCoinControlLowOutputText")->setToolTip(l7->toolTip());
    dialog->findChild<QLabel *>("labelCoinControlChangeText")->setToolTip(l8->toolTip());

    /* Insufficient funds */
    QLabel *label = dialog->findChild<QLabel *>("labelCoinControlInsuffFunds");
    if(label) label->setVisible(nChange < 0);
}

void CoinControl::updateView() {
    bool treeMode = ui->radioTreeMode->isChecked();
    int i;

    ui->treeWidget->clear();
    /* Performance, otherwise updateLabels would be called for every checked checkbox */
    ui->treeWidget->setEnabled(false);
    ui->treeWidget->setAlternatingRowColors(!treeMode);
    QFlags<Qt::ItemFlag> flgCheckbox =
      (Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable);
    QFlags<Qt::ItemFlag> flgTristate =
      (Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsUserCheckable | Qt::ItemIsTristate);

    int nDisplayUnit = CoinUnits::ORB;
    if(model && model->getOptionsModel())
      nDisplayUnit = model->getOptionsModel()->getDisplayUnit();

    map<QString, vector<COutput> > mapCoins;
    model->listCoins(mapCoins);

    BOOST_FOREACH(PAIRTYPE(QString, vector<COutput>) coins, mapCoins) {
        QTreeWidgetItem *itemWalletAddress = new QTreeWidgetItem();
        QString sWalletAddress = coins.first;
        QString sWalletLabel = "";

        if(model->getAddressTableModel())
          sWalletLabel = model->getAddressTableModel()->labelForAddress(sWalletAddress);

        if(!sWalletLabel.length())
          sWalletLabel = tr("(no label)");

        if(treeMode) {
            ui->treeWidget->addTopLevelItem(itemWalletAddress);

            itemWalletAddress->setFlags(flgTristate);
            itemWalletAddress->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);

            for(i = 0; i < ui->treeWidget->columnCount(); i++)
              itemWalletAddress->setBackground(i, QColor(248, 247, 246));

            itemWalletAddress->setText(COLUMN_LABEL, sWalletLabel);

            itemWalletAddress->setText(COLUMN_ADDRESS, sWalletAddress);
        }

        int64 nSum = 0;
        double dPrioritySum = 0;
        int nChildren = 0;
        int nInputSum = 0;
        uint64 nTxWeight = 0;
        uint64 nTxWeightTotal = 0;
        BOOST_FOREACH(const COutput &out, coins.second) {
            /* 148 bytes if compressed public key,
             * 180 bytes if uncompressed */
            int nInputSize = 148;

            nSum += out.tx->vout[out.i].nValue;
            nChildren++;

            /* Calculate stake weight */
            model->getStakeWeightQuick(out.tx->GetTxTime(), out.tx->vout[out.i].nValue, nTxWeight);
            nTxWeightTotal += nTxWeight;

            QTreeWidgetItem *itemOutput;
            if(treeMode) {
                itemOutput = new QTreeWidgetItem(itemWalletAddress);
            } else {
                itemOutput = new QTreeWidgetItem(ui->treeWidget);
            }
            itemOutput->setFlags(flgCheckbox);
            itemOutput->setCheckState(COLUMN_CHECKBOX,Qt::Unchecked);

            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.tx->vout[out.i].scriptPubKey, outputAddress)) {
                sAddress = CCoinAddress(outputAddress).ToString().c_str();

                /* If list mode or change, then show address.
                 * In tree mode, address is not shown again for direct wallet address outputs */
                if(!treeMode || (!(sAddress == sWalletAddress)))
                  itemOutput->setText(COLUMN_ADDRESS, sAddress);

                CPubKey pubkey;
                CKeyID *keyid = boost::get<CKeyID>(&outputAddress);
                if(keyid && model->getPubKey(*keyid, pubkey) && !pubkey.IsCompressed())
                  nInputSize = 180;
            }

            if(!(sAddress == sWalletAddress)) {
                /* Tool tip from where the change comes from */
                itemOutput->setToolTip(COLUMN_LABEL, tr("change from %1 (%2)") \
                  .arg(sWalletLabel).arg(sWalletAddress));
                itemOutput->setText(COLUMN_LABEL, tr("(change)"));
            } else if(!treeMode) {
                QString sLabel = "";
                if(model->getAddressTableModel())
                  sLabel = model->getAddressTableModel()->labelForAddress(sAddress);
                if(!sLabel.length())
                  sLabel = tr("(no label)");
                itemOutput->setText(COLUMN_LABEL, sLabel); 
            }

            itemOutput->setText(COLUMN_AMOUNT,
              CoinUnits::format(nDisplayUnit, out.tx->vout[out.i].nValue));

            itemOutput->setText(COLUMN_AMOUNT_INT64,
              strPad(QString::number(out.tx->vout[out.i].nValue), 15, " "));

            itemOutput->setText(COLUMN_DATE,
              QDateTime::fromTime_t(out.tx->GetTxTime()).toString("yy-MM-dd hh:mm"));

            itemOutput->setText(COLUMN_CONFIRMATIONS,
              strPad(QString::number(out.nDepth), 8, " "));

            /* 78 = 2 * 34 + 10 */
            double dPriority = ((double)out.tx->vout[out.i].nValue /
              (nInputSize + 78)) * (out.nDepth + 1);

            itemOutput->setText(COLUMN_PRIORITY,
              CoinControl::getPriorityLabel(dPriority));

            itemOutput->setText(COLUMN_PRIORITY_INT64,
               strPad(QString::number((int64)dPriority), 20, " "));

            dPrioritySum += (double)out.tx->vout[out.i].nValue  * (out.nDepth + 1);

            nInputSum += nInputSize;

            itemOutput->setText(COLUMN_WEIGHT, strPad(QString::number(nTxWeight), 8, " "));

            uint256 txhash = out.tx->GetHash();
            itemOutput->setText(COLUMN_TXHASH, txhash.GetHex().c_str());

            itemOutput->setText(COLUMN_VOUT_INDEX, QString::number(out.i));

            /* Set check box */
            if(control->IsSelected(txhash, out.i))
              itemOutput->setCheckState(COLUMN_CHECKBOX,Qt::Checked);
        }

        if(treeMode) {
            dPrioritySum = dPrioritySum / (nInputSum + 78);

            itemWalletAddress->setText(COLUMN_CHECKBOX,
              "(" + QString::number(nChildren) + ")");

            itemWalletAddress->setText(COLUMN_AMOUNT,
              CoinUnits::format(nDisplayUnit, nSum));

            itemWalletAddress->setText(COLUMN_AMOUNT_INT64,
              strPad(QString::number(nSum), 15, " "));

            itemWalletAddress->setText(COLUMN_PRIORITY,
              CoinControl::getPriorityLabel(dPrioritySum));

            itemWalletAddress->setText(COLUMN_PRIORITY_INT64,
              strPad(QString::number((int64)dPrioritySum), 20, " "));

            itemWalletAddress->setText(COLUMN_WEIGHT,
              strPad(QString::number((uint64)nTxWeightTotal), 8, " "));
        }
    }

    if(treeMode) {
        /* Expand all partially selected */
        for(i = 0; i < ui->treeWidget->topLevelItemCount(); i++) {
            if(ui->treeWidget->topLevelItem(i)->checkState(COLUMN_CHECKBOX) == Qt::PartiallyChecked)
              ui->treeWidget->topLevelItem(i)->setExpanded(true);
        }
    }

    sortView(sortColumn, sortOrder);
    ui->treeWidget->setEnabled(true);
}

CoinControlTreeWidget::CoinControlTreeWidget(QWidget *parent) :
    QTreeWidget(parent) { }

void CoinControlTreeWidget::keyPressEvent(QKeyEvent *event) {

    if(event->key() == Qt::Key_Space) {
        /* Press space bar -> select checkbox */
        event->ignore();

        /* Avoids a crash if no item selected */
        if(!this->currentItem()) return;

        int COLUMN_CHECKBOX = 0;
        this->currentItem()->setCheckState(COLUMN_CHECKBOX,
          ((this->currentItem()->checkState(COLUMN_CHECKBOX) == Qt::Checked) ?
          Qt::Unchecked : Qt::Checked));
    } else if(event->key() == Qt::Key_Escape) {
        /* Press escape -> close dialogue */
        event->ignore();
        ((CoinControl *) this->parentWidget())->done(QDialog::Accepted);
    } else {
        this->QTreeWidget::keyPressEvent(event);
    }

}
