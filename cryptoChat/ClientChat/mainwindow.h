#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpSocket>
#include <QDateTime>
#include <sstream>
#include "Crypto.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void ConnectToServer();
    void DisconnectFromServer();
    void SendMessageToServer();
    void ReceiveMessageFromServer();
    void handleKeyExchange(const std::string &data);

private:
    Ui::MainWindow *ui;
    QTcpSocket *clnt_sock;
    CryptoManager *crypto;
    mpz_class sessionKey;
    QString username;
};

#endif // MAINWINDOW_H