#include "walletstyles.h"

#include <QStringList>

WalletStyles::WalletStyles(QObject *parent):
    QAbstractListModel(parent), style_list(availableStyles()) { }

QList<WalletStyles::Style> WalletStyles::availableStyles() {
    QList<WalletStyles::Style> style_list;
    style_list.append(style0);
    style_list.append(style1);
    style_list.append(style2);
    style_list.append(style3);
    return(style_list);
}

QString WalletStyles::name(int style) {

    switch(style) {
        case(style0):
            return(QString("(default)"));
        case(style1):
            return(QString("standard gray"));
        case(style2):
            return(QString("extended gray"));
        case(style3):
            return(QString("extended green"));
        default:
            return(QString("???"));
    }
}

QString WalletStyles::description(int style) {

    switch(style) {
        case(style0):
            return(QString("Default wallet style"));
        case(style1):
            return(QString("Style with a horizontal gray icon bar"));
        case(style2):
            return(QString("Style with a vertical gray icon bar"));
        case(style3):
            return(QString("Style with a vertical green icon bar"));
        default:
            return(QString("???"));
    }
}

int WalletStyles::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent);
    return(style_list.size());
}

QVariant WalletStyles::data(const QModelIndex &index, int role) const {

    int row = index.row();
    if((row >= 0) && (row < style_list.size())) {
        Style style = style_list.at(row);
        switch(role) {
            case(Qt::EditRole):
            case(Qt::DisplayRole):
                return(QVariant(name(style)));
            case(Qt::ToolTipRole):
                return(QVariant(description(style)));
            case(StyleRole):
                return(QVariant(static_cast<int>(style)));
        }
    }

    return(QVariant());
}
