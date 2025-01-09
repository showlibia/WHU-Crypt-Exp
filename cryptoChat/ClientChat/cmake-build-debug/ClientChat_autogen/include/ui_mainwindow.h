/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.15.16
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QGridLayout *gridLayout_2;
    QHBoxLayout *qh_tip;
    QLabel *tip_label;
    QLineEdit *tip_edit;
    QTextEdit *recieve_edit;
    QGridLayout *client_qg;
    QHBoxLayout *horizontalLayout;
    QPushButton *cancel_pb;
    QPushButton *send_pb;
    QHBoxLayout *horizontalLayout_2;
    QPushButton *disconnect_pb;
    QPushButton *connect_pb;
    QTextEdit *send_edit;
    QGridLayout *gridLayout;
    QLineEdit *username_edit;
    QLabel *host_label;
    QLabel *username_label;
    QLineEdit *host_edit;
    QLabel *port_label;
    QLineEdit *port_edit;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(834, 734);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        gridLayout_2 = new QGridLayout(centralwidget);
        gridLayout_2->setObjectName(QString::fromUtf8("gridLayout_2"));
        qh_tip = new QHBoxLayout();
        qh_tip->setObjectName(QString::fromUtf8("qh_tip"));
        tip_label = new QLabel(centralwidget);
        tip_label->setObjectName(QString::fromUtf8("tip_label"));

        qh_tip->addWidget(tip_label);

        tip_edit = new QLineEdit(centralwidget);
        tip_edit->setObjectName(QString::fromUtf8("tip_edit"));

        qh_tip->addWidget(tip_edit);


        gridLayout_2->addLayout(qh_tip, 0, 0, 1, 1);

        recieve_edit = new QTextEdit(centralwidget);
        recieve_edit->setObjectName(QString::fromUtf8("recieve_edit"));

        gridLayout_2->addWidget(recieve_edit, 1, 0, 1, 1);

        client_qg = new QGridLayout();
        client_qg->setObjectName(QString::fromUtf8("client_qg"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        cancel_pb = new QPushButton(centralwidget);
        cancel_pb->setObjectName(QString::fromUtf8("cancel_pb"));

        horizontalLayout->addWidget(cancel_pb);

        send_pb = new QPushButton(centralwidget);
        send_pb->setObjectName(QString::fromUtf8("send_pb"));

        horizontalLayout->addWidget(send_pb);


        client_qg->addLayout(horizontalLayout, 1, 0, 1, 1);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        disconnect_pb = new QPushButton(centralwidget);
        disconnect_pb->setObjectName(QString::fromUtf8("disconnect_pb"));

        horizontalLayout_2->addWidget(disconnect_pb);

        connect_pb = new QPushButton(centralwidget);
        connect_pb->setObjectName(QString::fromUtf8("connect_pb"));

        horizontalLayout_2->addWidget(connect_pb);


        client_qg->addLayout(horizontalLayout_2, 1, 1, 1, 1);

        send_edit = new QTextEdit(centralwidget);
        send_edit->setObjectName(QString::fromUtf8("send_edit"));

        client_qg->addWidget(send_edit, 0, 0, 1, 1);

        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        username_edit = new QLineEdit(centralwidget);
        username_edit->setObjectName(QString::fromUtf8("username_edit"));

        gridLayout->addWidget(username_edit, 0, 1, 1, 1);

        host_label = new QLabel(centralwidget);
        host_label->setObjectName(QString::fromUtf8("host_label"));

        gridLayout->addWidget(host_label, 1, 0, 1, 1);

        username_label = new QLabel(centralwidget);
        username_label->setObjectName(QString::fromUtf8("username_label"));

        gridLayout->addWidget(username_label, 0, 0, 1, 1);

        host_edit = new QLineEdit(centralwidget);
        host_edit->setObjectName(QString::fromUtf8("host_edit"));

        gridLayout->addWidget(host_edit, 1, 1, 1, 1);

        port_label = new QLabel(centralwidget);
        port_label->setObjectName(QString::fromUtf8("port_label"));

        gridLayout->addWidget(port_label, 2, 0, 1, 1);

        port_edit = new QLineEdit(centralwidget);
        port_edit->setObjectName(QString::fromUtf8("port_edit"));

        gridLayout->addWidget(port_edit, 2, 1, 1, 1);


        client_qg->addLayout(gridLayout, 0, 1, 1, 1);


        gridLayout_2->addLayout(client_qg, 2, 0, 1, 1);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 834, 21));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        tip_label->setText(QCoreApplication::translate("MainWindow", "System prompt Info", nullptr));
        cancel_pb->setText(QCoreApplication::translate("MainWindow", "Cancel", nullptr));
        send_pb->setText(QCoreApplication::translate("MainWindow", "Send", nullptr));
        disconnect_pb->setText(QCoreApplication::translate("MainWindow", "Disconnect", nullptr));
        connect_pb->setText(QCoreApplication::translate("MainWindow", "Connect", nullptr));
        username_edit->setText(QCoreApplication::translate("MainWindow", "Andy", nullptr));
        host_label->setText(QCoreApplication::translate("MainWindow", "HostAddress", nullptr));
        username_label->setText(QCoreApplication::translate("MainWindow", "Username", nullptr));
        host_edit->setText(QCoreApplication::translate("MainWindow", "127.0.0.1", nullptr));
        port_label->setText(QCoreApplication::translate("MainWindow", "Port", nullptr));
        port_edit->setText(QCoreApplication::translate("MainWindow", "8080", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
