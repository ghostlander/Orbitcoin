#ifndef COINCONTROL_H
#define COINCONTROL_H

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QKeyEvent>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidgetItem>

namespace Ui {
    class CoinControl;
}

class WalletModel;
class CCoinControl;

class CoinControl : public QDialog {
    Q_OBJECT

public:
    explicit CoinControl(QWidget *parent = 0);
    ~CoinControl();

    void setModel(WalletModel *model);

    /* static because also called from sendcoinsdialog */
    static void updateLabels(WalletModel *, QDialog *);
    static QString getPriorityLabel(double);

    static QList<qint64> payAmounts;
    static CCoinControl *control;

private:
    Ui::CoinControl *ui;
    WalletModel *model;
    int sortColumn;
    Qt::SortOrder sortOrder;

    QMenu *contextMenu;
    QTreeWidgetItem *contextMenuItem;
    QAction *copyTransactionHashAction;

    QString strPad(QString, int, QString);
    void sortView(int, Qt::SortOrder);
    void updateView();

    enum
    {
        COLUMN_CHECKBOX,
        COLUMN_AMOUNT,
        COLUMN_LABEL,
        COLUMN_ADDRESS,
        COLUMN_DATE,
        COLUMN_CONFIRMATIONS,
        COLUMN_PRIORITY,
        COLUMN_WEIGHT,
        COLUMN_TXHASH,
        COLUMN_VOUT_INDEX,
        COLUMN_AMOUNT_INT64,
        COLUMN_PRIORITY_INT64
    };

private slots:
    void showMenu(const QPoint &);
    void copyAmount();
    void copyLabel();
    void copyAddress();
    void copyTransactionHash();
    void clipboardQuantity();
    void clipboardAmount();
    void clipboardFee();
    void clipboardNetAmount();
    void clipboardBytes();
    void clipboardPriority();
    void clipboardLowOutput();
    void clipboardChange();
    void radioTreeMode(bool);
    void radioListMode(bool);
    void viewItemChanged(QTreeWidgetItem *, int);
    void headerSectionClicked(int);
    void buttonBoxClicked(QAbstractButton *);
    void buttonSelectAllClicked();
};

class CoinControlTreeWidget : public QTreeWidget {
    Q_OBJECT

public:
    explicit CoinControlTreeWidget(QWidget *parent = 0);

protected:
    virtual void keyPressEvent(QKeyEvent *event);
};

#endif /* COINCONTROL_H */
