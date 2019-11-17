#include "sendcoinsdialog.h"
#include "ui_sendcoinsdialog.h"

#include "init.h"
#include "base58.h"
#include "walletmodel.h"
#include "addresstablemodel.h"
#include "addressbookpage.h"
#include "coinunits.h"
#include "addressbookpage.h"
#include "optionsmodel.h"
#include "sendcoinsentry.h"
#include "guiutil.h"
#include "askpassphrasedialog.h"
#include "coincontrol.h"

#include <QMessageBox>
#include <QTextDocument>
#include <QScrollBar>
#include <QClipboard>

SendCoinsDialog::SendCoinsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SendCoinsDialog),
    model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->addButton->setIcon(QIcon());
    ui->clearButton->setIcon(QIcon());
    ui->sendButton->setIcon(QIcon());
#endif

#if (QT_VERSION >= 0x040700)
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->editTxComment->setPlaceholderText(tr("Enter a transaction comment up to 140 characters (NOTE: this information is public)"));
    ui->lineEditCoinControlChange->setPlaceholderText(tr("Enter an Orbitcoin address (e.g. oRBkGBRp3i8Cj1q4yeDh5nxz8ACj4TaH7D)"));
#endif

    addEntry();

    connect(ui->addButton, SIGNAL(clicked()), this, SLOT(addEntry()));
    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));

    /* The Coin Control */
    ui->lineEditCoinControlChange->setFont(GUIUtil::AddressFont());
    connect(ui->pushButtonCoinControl, SIGNAL(clicked()), this,
      SLOT(coinControlButtonClicked()));
    connect(ui->checkBoxCoinControlChange, SIGNAL(stateChanged(int)), this,
      SLOT(coinControlChangeChecked(int)));
    connect(ui->lineEditCoinControlChange, SIGNAL(textEdited(const QString &)), this,
      SLOT(coinControlChangeEdited(const QString &)));

    /* The Coin Control: clipboard actions */
    QAction *clipboardQuantityAction = new QAction(tr("Copy quantity"), this);
    QAction *clipboardAmountAction = new QAction(tr("Copy amount"), this);
    QAction *clipboardFeeAction = new QAction(tr("Copy fee"), this);
    QAction *clipboardNetAmountAction = new QAction(tr("Copy net amount"), this);
    QAction *clipboardBytesAction = new QAction(tr("Copy bytes"), this);
    QAction *clipboardPriorityAction = new QAction(tr("Copy priority"), this);
    QAction *clipboardLowOutputAction = new QAction(tr("Copy low output"), this);
    QAction *clipboardChangeAction = new QAction(tr("Copy change"), this);
    connect(clipboardQuantityAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardQuantity()));
    connect(clipboardAmountAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardAmount()));
    connect(clipboardFeeAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardFee()));
    connect(clipboardNetAmountAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardNetAmount()));
    connect(clipboardBytesAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardBytes()));
    connect(clipboardPriorityAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardPriority()));
    connect(clipboardLowOutputAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardLowOutput()));
    connect(clipboardChangeAction, SIGNAL(triggered()),
      this, SLOT(coinControlClipboardChange()));
    ui->labelCoinControlQuantity->addAction(clipboardQuantityAction);
    ui->labelCoinControlAmount->addAction(clipboardAmountAction);
    ui->labelCoinControlFee->addAction(clipboardFeeAction);
    ui->labelCoinControlNetAmount->addAction(clipboardNetAmountAction);
    ui->labelCoinControlBytes->addAction(clipboardBytesAction);
    ui->labelCoinControlPriority->addAction(clipboardPriorityAction);
    ui->labelCoinControlLowOutput->addAction(clipboardLowOutputAction);
    ui->labelCoinControlChange->addAction(clipboardChangeAction);

    fNewRecipientAllowed = true;
}

void SendCoinsDialog::setModel(WalletModel *model) {
    int i;

    this->model = model;

    QString txcomment = ui->editTxComment->text();

    if(model && model->getOptionsModel()) {

        for(i = 0; i < ui->entries->count(); ++i) {
            SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
            if(entry) entry->setModel(model);
        }

        setBalance(model->getBalance(), model->getStake(), model->getUnconfirmed(), model->getImmature());
        connect(model, SIGNAL(balanceChanged(qint64, qint64, qint64, qint64)), this,
          SLOT(setBalance(qint64, qint64, qint64, qint64)));
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this,
          SLOT(updateDisplayUnit()));

        /* The Coin Control */
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this,
          SLOT(coinControlUpdateLabels()));
        connect(model->getOptionsModel(), SIGNAL(coinControlFeaturesChanged(bool)), this,
          SLOT(coinControlFeatureChanged(bool)));
        connect(model->getOptionsModel(), SIGNAL(transactionFeeChanged(qint64)), this,
          SLOT(coinControlUpdateLabels()));
        ui->frameCoinControl->setVisible(model->getOptionsModel()->getCoinControlFeatures());
        coinControlUpdateLabels();
    }
}

SendCoinsDialog::~SendCoinsDialog()
{
    delete ui;
}

void SendCoinsDialog::on_sendButton_clicked() {
    QList<SendCoinsRecipient> recipients;
    bool valid = true;
    int i;

    if(!model || !model->getOptionsModel()) return;

    QString txcomment = ui->editTxComment->text();

    for(i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry) {
            if(entry->validate()) recipients.append(entry->getValue());
            else valid = false;
        }
    }

    if(!valid || recipients.isEmpty()) return;

    // Format confirmation message
    QStringList formatted;
    foreach(const SendCoinsRecipient &rcp, recipients) {
        QString amount = CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount);
        QString recipientElement = QString("<b>%1</b> ").arg(
          CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), rcp.amount));
        recipientElement.append(tr("to"));

        /* Add address with or without label */
        if(rcp.label.length() > 0) {
          recipientElement.append(QString(" %1 <span style='font-size:8px;'>%2</span><br />").arg(
            GUIUtil::HtmlEscape(rcp.label), rcp.address));
        } else {
            recipientElement.append(QString(" %1<br />").arg(rcp.address));
        }
        formatted.append(recipientElement);
    }

    fNewRecipientAllowed = false;

    WalletModel::UnlockContext ctx(model->requestUnlock());
    if(!ctx.isValid())
    {
        // Unlock wallet was cancelled
        fNewRecipientAllowed = true;
        return;
    }

    /* Prepare a transaction to get a fee estimate */
    WalletModelTransaction currentTransaction(recipients);
    WalletModel::SendCoinsReturn prepareStatus;
    if(model->getOptionsModel()->getCoinControlFeatures()) {
        prepareStatus = model->prepareTransaction(currentTransaction, txcomment,
          CoinControl::control);
    } else {
        prepareStatus = model->prepareTransaction(currentTransaction, txcomment);
    }

    QString strSendCoins = tr("Send");
    switch(prepareStatus.status) {
        case(WalletModel::InvalidAddress):
            QMessageBox::warning(this, tr("Send"),
              tr("The recipient address is not valid, please verify."),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::InvalidAmount):
            QMessageBox::warning(this, tr("Send"),
              tr("The amount to pay must be larger than 0."),
              QMessageBox::Ok, QMessageBox::Ok);
             break;
        case(WalletModel::AmountExceedsBalance):
            QMessageBox::warning(this, tr("Send"),
              tr("The amount exceeds your balance."),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::AmountWithFeeExceedsBalance):
            QMessageBox::warning(this, tr("Send"),
              tr("The total exceeds your balance if a %1 fee is included.") \
              .arg(CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(),
              currentTransaction.getTransactionFee())),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::DuplicateAddress):
            QMessageBox::warning(this, tr("Send"),
              tr("Duplicate address found, can only send to each address once per send operation."),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::TransactionCreationFailed):
            QMessageBox::warning(this, tr("Send"),
              tr("Error: payment failed!"),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::TransactionCommitFailed):
        case(WalletModel::Aborted):
        case(WalletModel::OK):
            break;
    }

    if(prepareStatus.status != WalletModel::OK) {
        fNewRecipientAllowed = true;
        return;
    }

    qint64 txFee = currentTransaction.getTransactionFee();
    QString questionString = tr("Are you sure you want to send?");
    questionString.append("<br /><br />%1");

    if(txFee > 0) {
        /* Append a fee string if a fee is required */
        questionString.append("<hr /><span style='color:#aa0000;'>");
        questionString.append(CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), txFee));
        questionString.append("</span> ");
        questionString.append(tr("added as a fee"));
    }

    if((txFee > 0) || (recipients.count() > 1)) {
        /* Add a total amount string if there are more then one recipient or a fee is required */
        questionString.append("<hr />");
        questionString.append(tr("Total amount %1").arg(
          CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(),
          currentTransaction.getTotalTransactionAmount() + txFee)));
    }

    QMessageBox::StandardButton retval = QMessageBox::question(this,
      tr("Payment confirmation"), questionString.arg(formatted.join("<br />")),
      QMessageBox::Yes|QMessageBox::Cancel, QMessageBox::Cancel);

    if(retval != QMessageBox::Yes) {
        fNewRecipientAllowed = true;
        return;
    }

    /* Send the prepared transaction */
    WalletModel::SendCoinsReturn sendstatus = model->sendCoins(currentTransaction);
    switch(sendstatus.status) {
        case(WalletModel::TransactionCommitFailed):
            QMessageBox::warning(this, tr("Send"),
              tr("Error: Transaction rejected. It might happen if some of the coins in your wallet have been spent already."),
              QMessageBox::Ok, QMessageBox::Ok);
            break;
        case(WalletModel::Aborted):
            break;
        case(WalletModel::OK):
            accept();
            CoinControl::control->UnSelectAll();
            coinControlUpdateLabels();
            break;
        default:
            break;
    }

    fNewRecipientAllowed = true;

}

void SendCoinsDialog::clear() {
    ui->editTxComment->clear();

    // Remove entries until only one left
    while(ui->entries->count())
    {
        delete ui->entries->takeAt(0)->widget();
    }
    addEntry();

    updateRemoveEnabled();

    ui->sendButton->setDefault(true);
}

void SendCoinsDialog::reject()
{
    clear();
}

void SendCoinsDialog::accept()
{
    clear();
}

SendCoinsEntry *SendCoinsDialog::addEntry()
{
    SendCoinsEntry *entry = new SendCoinsEntry(this);
    entry->setModel(model);
    ui->entries->addWidget(entry);

    connect(entry, SIGNAL(removeEntry(SendCoinsEntry *)),
      this, SLOT(removeEntry(SendCoinsEntry *)));
    connect(entry, SIGNAL(payAmountChanged()),
      this, SLOT(coinControlUpdateLabels()));

    updateRemoveEnabled();

    // Focus the field, so that entry can start immediately
    entry->clear();
    entry->setFocus();
    ui->scrollAreaWidgetContents->resize(ui->scrollAreaWidgetContents->sizeHint());
    QCoreApplication::instance()->processEvents();
    QScrollBar* bar = ui->scrollArea->verticalScrollBar();
    if(bar)
        bar->setSliderPosition(bar->maximum());
    return entry;
}

void SendCoinsDialog::updateRemoveEnabled()
{
    // Remove buttons are enabled as soon as there is more than one send-entry
    bool enabled = (ui->entries->count() > 1);
    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            entry->setRemoveEnabled(enabled);
        }
    }
    setupTabChain(0);
    coinControlUpdateLabels();
}

void SendCoinsDialog::removeEntry(SendCoinsEntry* entry)
{
    delete entry;
    updateRemoveEnabled();
}

QWidget *SendCoinsDialog::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->editTxComment);
    prev = ui->editTxComment;

    for(int i = 0; i < ui->entries->count(); ++i)
    {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(i)->widget());
        if(entry)
        {
            prev = entry->setupTabChain(prev);
        }
    }
    QWidget::setTabOrder(prev, ui->addButton);
    QWidget::setTabOrder(ui->addButton, ui->sendButton);
    return ui->sendButton;
}

void SendCoinsDialog::setAddress(const QString &address) {
    SendCoinsEntry *entry = 0;

    /* Replace the first entry if it is still unused */
    if(ui->entries->count() == 1) {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry *>(ui->entries->itemAt(0)->widget());
        if(first->isClear()) entry = first;
    }

    if(!entry) entry = addEntry();

    entry->setAddress(address);
}

void SendCoinsDialog::pasteEntry(const SendCoinsRecipient &rv)
{
    if(!fNewRecipientAllowed)
        return;

    SendCoinsEntry *entry = 0;
    // Replace the first entry if it is still unused
    if(ui->entries->count() == 1)
    {
        SendCoinsEntry *first = qobject_cast<SendCoinsEntry*>(ui->entries->itemAt(0)->widget());
        if(first->isClear())
        {
            entry = first;
        }
    }
    if(!entry)
    {
        entry = addEntry();
    }

    entry->setValue(rv);
    coinControlUpdateLabels();
}

bool SendCoinsDialog::handleURI(const QString &uri) {
    SendCoinsRecipient rv;

    if(GUIUtil::parseCoinURI(uri, &rv)) {
        CCoinAddress address(rv.address.toStdString());
        if(!address.IsValid()) return(false);
        pasteEntry(rv);
        return(true);
    }

    return(false);
}

void SendCoinsDialog::setBalance(qint64 balance, qint64 stake, qint64 unconfirmed,
  qint64 immature) {
    Q_UNUSED(stake);
    Q_UNUSED(unconfirmed);
    Q_UNUSED(immature);

    if(model && model->getOptionsModel()) {
        ui->labelBalance->setText(
          CoinUnits::formatWithUnit(model->getOptionsModel()->getDisplayUnit(), balance));
    }
}

void SendCoinsDialog::updateDisplayUnit() {
    setBalance(model->getBalance(), 0, 0, 0);
}


/* The Coin Control */

/* Copy label "Quantity" to clipboard */
void SendCoinsDialog::coinControlClipboardQuantity() {
    GUIUtil::setClipboard(ui->labelCoinControlQuantity->text());
}

/* Copy label "Amount" to clipboard */
void SendCoinsDialog::coinControlClipboardAmount() {
    GUIUtil::setClipboard(ui->labelCoinControlAmount->text() \
      .left(ui->labelCoinControlAmount->text().indexOf(" ")));
}

/* Copy label "Fee" to clipboard */
void SendCoinsDialog::coinControlClipboardFee() {
    GUIUtil::setClipboard(ui->labelCoinControlFee->text() \
      .left(ui->labelCoinControlFee->text().indexOf(" ")));
}

/* Copy label "After fee" to clipboard */
void SendCoinsDialog::coinControlClipboardNetAmount() {
    GUIUtil::setClipboard(ui->labelCoinControlNetAmount->text() \
      .left(ui->labelCoinControlNetAmount->text().indexOf(" ")));
}

/* Copy label "Bytes" to clipboard */
void SendCoinsDialog::coinControlClipboardBytes() {
    GUIUtil::setClipboard(ui->labelCoinControlBytes->text());
}

/* Copy label "Priority" to clipboard */
void SendCoinsDialog::coinControlClipboardPriority() {
    GUIUtil::setClipboard(ui->labelCoinControlPriority->text());
}

/* Copy label "Low output" to clipboard */
void SendCoinsDialog::coinControlClipboardLowOutput() {
    GUIUtil::setClipboard(ui->labelCoinControlLowOutput->text());
}

/* Copy label "Change" to clipboard */
void SendCoinsDialog::coinControlClipboardChange() {
    GUIUtil::setClipboard(ui->labelCoinControlChange->text() \
      .left(ui->labelCoinControlChange->text().indexOf(" ")));
}

/* Settings menu, to enable/disable the Coin Control */
void SendCoinsDialog::coinControlFeatureChanged(bool checked) {
    ui->frameCoinControl->setVisible(checked);

    /* Disabled */
    if(!checked && model) CoinControl::control->SetNull();
}

/* Button inputs -> show the actual Coin Control dialogue */
void SendCoinsDialog::coinControlButtonClicked() {
    CoinControl dlg;
    dlg.setModel(model);
    dlg.exec();
    coinControlUpdateLabels();
}

/* Checkbox driven enforced change address */
void SendCoinsDialog::coinControlChangeChecked(int state) {

    if(model) {
        if(state == Qt::Checked) {
            CoinControl::control->destChange =
              CCoinAddress(ui->lineEditCoinControlChange->text().toStdString()).Get();
        } else {
            CoinControl::control->destChange = CNoDestination();
        }
    }

    ui->lineEditCoinControlChange->setEnabled((state == Qt::Checked));
    ui->labelCoinControlChangeLabel->setVisible((state == Qt::Checked));
}

/* Custom change address changed */
void SendCoinsDialog::coinControlChangeEdited(const QString &text) {

    if(!model) return;

    CoinControl::control->destChange = CCoinAddress(text.toStdString()).Get();

    /* Label for the change address */
    ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:black;}");
    if(text.isEmpty()) {
        ui->labelCoinControlChangeLabel->setText("");
    } else if(!CCoinAddress(text.toStdString()).IsValid()) {
        ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");
        ui->labelCoinControlChangeLabel->setText(tr("Warning: invalid address"));
    } else {
        QString associatedLabel = model->getAddressTableModel()->labelForAddress(text);
        if(!associatedLabel.isEmpty()) {
            ui->labelCoinControlChangeLabel->setText(associatedLabel);
        } else {
            CPubKey pubkey;
            CKeyID keyid;
            CCoinAddress(text.toStdString()).GetKeyID(keyid);   
            if(model->getPubKey(keyid, pubkey)) {
                ui->labelCoinControlChangeLabel->setText(tr("(no label)"));
            } else {
                ui->labelCoinControlChangeLabel->setStyleSheet("QLabel{color:red;}");
                ui->labelCoinControlChangeLabel->setText(tr("Warning: unknown change address"));
            }
        }
    }
}

/* Update labels */
void SendCoinsDialog::coinControlUpdateLabels() {
    int i;

    if(!model) return;

    /* Set pay amounts */
    CoinControl::payAmounts.clear();
    for(i = 0; i < ui->entries->count(); ++i) {
        SendCoinsEntry *entry = qobject_cast<SendCoinsEntry *>(ui->entries->itemAt(i)->widget());
        if(entry) CoinControl::payAmounts.append(entry->getValue().amount);
    }

    if(CoinControl::control->HasSelected()) {
        /* Actual calculation */
        CoinControl::updateLabels(model, this);

        /* Show stats */
        ui->labelCoinControlAutomaticallySelected->hide();
        ui->widgetCoinControl->show();
    } else {
        /* Hide stats */
        ui->labelCoinControlAutomaticallySelected->show();
        ui->widgetCoinControl->hide();
        ui->labelCoinControlInsuffFunds->hide();
    }
}
