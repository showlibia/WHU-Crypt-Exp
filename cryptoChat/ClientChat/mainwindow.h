#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpSocket>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QDateTime>


QT_BEGIN_NAMESPACE
namespace Ui {
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

private:
    Ui::MainWindow *ui;
	QTcpSocket* clnt_sock;
	QString username;
};
#endif // MAINWINDOW_H
