#ifndef WALLETSTYLES_H
#define WALLETSTYLES_H

#include <QString>
#include <QAbstractListModel>

/* Wallet style definitions and descriptions */
class WalletStyles: public QAbstractListModel {
    Q_OBJECT

public:
    explicit WalletStyles(QObject *parent);

    enum Style {
        style0,
        style1,
        style2,
        style3
    };

    /* List of styles */
    static QList<Style> availableStyles();
    /* Style name (drop down box) */
    static QString name(int style);
    /* Style description (tool tip) */
    static QString description(int style);

    /* nQtStyle */
    enum RoleIndex {
        StyleRole = Qt::UserRole
    };

    int rowCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;

private:
    QList<WalletStyles::Style> style_list;

};

#endif /* WALLETSTYLES_H */
