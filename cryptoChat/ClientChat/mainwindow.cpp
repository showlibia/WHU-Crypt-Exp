#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QMessageBox>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("ChatRoom");
    clnt_sock = new QTcpSocket(this);
    crypto = new CryptoManager();
    sha256 = new SHA256();
    if (!crypto->generateRSAKeys(2048))
    {
        QMessageBox::critical(this, "error", "RSA error");
        return;
    }
    sessionKey = 0;
    connect(ui->connect_pb, &QPushButton::clicked, this, &MainWindow::ConnectToServer);
    connect(ui->disconnect_pb, &QPushButton::clicked, this, &MainWindow::DisconnectFromServer);
    connect(ui->send_pb, &QPushButton::clicked, this, &MainWindow::SendMessageToServer);
    connect(clnt_sock, &QTcpSocket::readyRead, this, &MainWindow::ReceiveMessageFromServer);
    connect(clnt_sock, &QTcpSocket::connected, this, [this]()
            { ui->tip_edit->setText("connected"); });
    connect(clnt_sock, &QTcpSocket::disconnected, this, [this]()
            {
        sessionKey = 0;
        ui->tip_edit->setText("Disconnected"); });
}

MainWindow::~MainWindow()
{
    delete crypto;
    delete ui;
}

void MainWindow::ConnectToServer()
{
    username = ui->username_edit->text();
    QString hostAddress = ui->host_edit->text();
    quint16 port = ui->port_edit->text().toUShort();
    qDebug() << "Connecting to host:" << hostAddress << "on port:" << port;
    clnt_sock->connectToHost(hostAddress, port);
    if (hostAddress.isEmpty() || port == 0)
    {
        qDebug() << "Invalid host address or port.";
        ui->tip_edit->setText("Please enter a valid IP and port.");
        return;
    }
    qDebug() << "Socket state:" << clnt_sock->state();
    if (!clnt_sock->waitForConnected(5000))
    {
        qDebug() << "Connection failed. Error:" << clnt_sock->errorString();
        ui->tip_edit->setText("Failed to connect: " + clnt_sock->errorString());
    }
    else
    {
        qDebug() << "Connection successful. State:" << clnt_sock->state();
        ui->tip_edit->setText("connected");
    }
}

void MainWindow::DisconnectFromServer()
{
    clnt_sock->disconnectFromHost();
    if (clnt_sock->state() == QTcpSocket::ConnectedState)
    {
        clnt_sock->waitForDisconnected();
    }
    sessionKey = 0;
    ui->tip_edit->setText("disconnected");
}

void MainWindow::handleKeyExchange(const std::string &data)
{
    std::string key_exchange = "KEY_EXCHANGE|";
    if (data.compare(0, key_exchange.length(), key_exchange) == 0)
    {
        try
        {
            std::vector<std::string> parts;
            std::string received = data;
            size_t pos = 0;
            std::string token;
            while ((pos = received.find('|')) != std::string::npos)
            {
                token = received.substr(0, pos);
                parts.push_back(token);
                received = received.substr(pos + 1);
            }
            parts.push_back(received);
            if (parts.size() != 5)
            {
                throw std::runtime_error("Invalid key exchange format");
            }
            mpz_class server_e = crypto->hexTompz_class(parts[1]);
            mpz_class server_n = crypto->hexTompz_class(parts[2]);
            if (!crypto->hasStoredServerKey())
            {
                QMessageBox::StandardButton reply;
                QString msg = QString("Server's public key fingerprint:\nE: %1\nN: %2\n\nDo you trust this server?")
                                  .arg(QString::fromStdString(parts[1]))
                                  .arg(QString::fromStdString(parts[2]));
                reply = QMessageBox::question(this, "Trust Server?", msg,
                                              QMessageBox::Yes | QMessageBox::No);
                if (reply == QMessageBox::No)
                {
                    DisconnectFromServer();
                    return;
                }
                if (!crypto->saveServerKey(server_e, server_n))
                {
                    QMessageBox::critical(this, "Error", "Failed to save server key");
                    DisconnectFromServer();
                    return;
                }
            }
            else
            {
                if (!crypto->verifyServerKey(server_e, server_n))
                {
                    QMessageBox::critical(this, "Error",
                                          "Server key mismatch! Potential security risk!");
                    DisconnectFromServer();
                    return;
                }
            }
            crypto->setPeerRSAKey(server_e, server_n);
            mpz_class server_dh_public = crypto->hexTompz_class(parts[3]);
            mpz_class server_signature = crypto->hexTompz_class(parts[4]);
            if (!crypto->verifySignature(server_dh_public, server_signature))
            {
                QMessageBox::critical(this, "Error", "Invalid server signature");
                DisconnectFromServer();
                return;
            }
            if (!crypto->generateDHKeys())
            {
                QMessageBox::critical(this, "Error", "Failed to generate DH keys");
                DisconnectFromServer();
                return;
            }
            mpz_class shared_secret = crypto->computeSharedSecret(server_dh_public);
            sessionKey = shared_secret;
            size_t count = (mpz_sizeinbase(shared_secret.get_mpz_t(), 2) + 7) / 8;
            std::vector<unsigned char> secret_bytes(count);
            size_t written1;
            mpz_export(secret_bytes.data(), &written1, 1, 1, 1, 0, shared_secret.get_mpz_t());
            std::vector<uint8_t> full = sha256->hash(secret_bytes.data(), secret_bytes.size());
            aesKey = std::vector<uint8_t>(full.begin(), full.begin() + 16);
            std::cout << "key: " << sessionKey << std::endl;
            std::string client_dh_hex = crypto->mpz_classToHex(crypto->getDHPublicValue());
            mpz_class client_signature = crypto->signData(crypto->getDHPublicValue());
            std::string signature_hex = crypto->mpz_classToHex(client_signature);
            std::ostringstream oss;
            oss << "KEY_EXCHANGE|" << crypto->mpz_classToHex(crypto->getRSAPublicKey_e()) << "|"
                << crypto->mpz_classToHex(crypto->getRSAPublicKey_n()) << "|"
                << client_dh_hex << "|" << signature_hex;
            std::string msg = oss.str();
            QByteArray msg_bytes(msg.c_str(), msg.length());
            qint64 written = 0;
            while (written < msg_bytes.size())
            {
                qint64 bytes = clnt_sock->write(msg_bytes.mid(written));
                if (bytes <= 0)
                {
                    QMessageBox::critical(this, "Error", "Failed to send key exchange data");
                    DisconnectFromServer();
                    return;
                }
                written += bytes;
            }
            clnt_sock->flush();
        }
        catch (const std::exception &e)
        {
            QMessageBox::critical(this, "Error", "Failed to exchange keys: " + QString(e.what()));
            DisconnectFromServer();
            return;
        }
    }
}

void MainWindow::SendMessageToServer()
{
    if (!clnt_sock || clnt_sock->state() != QTcpSocket::ConnectedState)
    {
        QMessageBox::warning(this, "Warning", "Not connected to server");
        return;
    }
    if (sessionKey == 0)
    {
        QMessageBox::warning(this, "Warning", "Not connected securely");
        return;
    }
    QString message_q = ui->send_edit->toPlainText();
    if (message_q.isEmpty())
    {
        return;
    }
    try
    {
        std::string message = "[" + username.toStdString() + "]: " + message_q.toStdString();
        std::string encrypted = crypto->encryptAES(message, aesKey);
        if (clnt_sock->write(encrypted.c_str(), encrypted.length()) == -1)
        {
            QMessageBox::critical(this, "Error", "Failed to send message");
            return;
        }
        std::cout << "Sent: " << message << std::endl;
        ui->send_edit->clear();
    }
    catch (const std::exception &e)
    {
        QMessageBox::critical(this, "Error", "Failed to process message: " + QString(e.what()));
    }
}

void MainWindow::ReceiveMessageFromServer()
{
    QByteArray data = clnt_sock->readAll();
    std::vector<uint8_t> received_data(data.begin(), data.end());
    std::string received(received_data.begin(), received_data.end());
    if (sessionKey == 0)
    {
        std::cout << "Received: " << received << std::endl;
        std::string key_exchange = "KEY_EXCHANGE|";
        if (received.compare(0, key_exchange.length(), key_exchange) == 0)
        {
            handleKeyExchange(received);
            return;
        }
        else
        {
            return;
        }
    }
    if (sessionKey != 0)
    {
        if (received == "KEY_EXCHANGE_COMPLETE")
        {
            ui->tip_edit->setText("Connected securely");
            return;
        }
        std::string decrypted = crypto->decryptAES(received, aesKey);
        std::cout << "Received: " << std::string(received_data.begin(), received_data.end()) << std::endl;
        QString msg = QString::fromStdString(decrypted);
        int end = msg.indexOf(']');
        if (end > 0)
        {
            QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
            QString msg_head = msg.mid(0, end + 1) + " " + timestamp + "\n";
            QString msg_content = msg.mid(end + 1);
            if (msg.mid(1, end - 1).contains(username))
            {
                msg_head = QString("<b><span style='color:lightgreen;'>%1</span></b>").arg(msg_head);
            }
            else
            {
                msg_head = QString("<b><span style='color:lightblue;'>%1</span></b>").arg(msg_head);
            }
            ui->recieve_edit->append(msg_head + msg_content);
        }
    }
}