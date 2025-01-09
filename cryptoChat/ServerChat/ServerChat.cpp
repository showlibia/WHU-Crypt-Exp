#include "ServerChat.h"

typedef int socket_t;
const socket_t INVALID_SOCKET_FD = -1;
#define CLOSE_SOCKET close
#define SOCKET_ERROR_CHECK(x) (x == -1)

void server_epoll()
{
    CryptoManager crypto;
    SHA256 sha256;
    if (!sha256.test())
    {
        std::cerr << "SHA256 implementation verification failed!" << std::endl;
        return;
    }
    std::cout << "SHA256 implementation verified successfully." << std::endl;
    if (!crypto.generateRSAKeys(2048))
    {
        std::cerr << "RSA error" << std::endl;
        return;
    }
    std::cout << "RSA keys generated" << std::endl;
    std::vector<socket_t> clnt_sockets;
    std::map<socket_t, mpz_class> sessionKeys;
    std::map<socket_t, CryptoManager::RSAKeys> peerRSAKeys;
    std::map<socket_t, std::vector<uint8_t>> aesKeys;
    socket_t serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (serv_sock == INVALID_SOCKET_FD)
    {
        std::cerr << "socket() error" << std::endl;
        return;
    }
    int opt = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8080);
    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        std::cerr << "bind() error" << std::endl;
        CLOSE_SOCKET(serv_sock);
        return;
    }
    if (listen(serv_sock, 5) == -1)
    {
        std::cerr << "listen() error" << std::endl;
        CLOSE_SOCKET(serv_sock);
        return;
    }
    std::cout << "Server started" << std::endl;
    fd_set reads, copy_reads;
    FD_ZERO(&reads);
    FD_SET(serv_sock, &reads);
    int max_fd = serv_sock;
    char buffer[BUFSIZ];
    while (true)
    {
        copy_reads = reads;
        int event_count = select(max_fd + 1, &copy_reads, nullptr, nullptr, nullptr);
        if (SOCKET_ERROR_CHECK(event_count))
        {
            std::cerr << "select() error" << std::endl;
            break;
        }
        for (int i = 0; i <= max_fd; i++)
        {
            if (FD_ISSET(i, &copy_reads))
            {
                if (i == serv_sock)
                {
                    struct sockaddr_in clnt_addr;
                    socklen_t clnt_sz = sizeof(clnt_addr);
                    socket_t clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_sz);
                    if (clnt_sock == INVALID_SOCKET_FD)
                    {
                        std::cerr << "accept() error" << std::endl;
                        continue;
                    }
                    FD_SET(clnt_sock, &reads);
                    if (clnt_sock > max_fd)
                        max_fd = clnt_sock;
                    clnt_sockets.push_back(clnt_sock);
                    std::string rsa_e_hex = crypto.mpz_classToHex(crypto.getRSAPublicKey_e());
                    std::string rsa_n_hex = crypto.mpz_classToHex(crypto.getRSAPublicKey_n());
                    if (!crypto.generateDHKeys())
                    {
                        std::cerr << "DH key generation failed" << std::endl;
                        CLOSE_SOCKET(clnt_sock);
                        FD_CLR(clnt_sock, &reads);
                        continue;
                    }
                    std::string dh_public_hex = crypto.mpz_classToHex(crypto.getDHPublicValue());
                    mpz_class signature = crypto.signData(crypto.getDHPublicValue());
                    std::string signature_hex = crypto.mpz_classToHex(signature);
                    std::ostringstream oss;
                    oss << "KEY_EXCHANGE|" << rsa_e_hex << "|" << rsa_n_hex << "|"
                        << dh_public_hex << "|" << signature_hex;
                    std::string msg = oss.str();
                    send(clnt_sock, msg.c_str(), msg.length(), 0);
                    std::cout << "Connected client: " << clnt_sock << std::endl;
                }
                else
                {
                    int str_len = recv(i, buffer, BUFSIZ, 0);
                    if (str_len <= 0)
                    {
                        FD_CLR(i, &reads);
                        CLOSE_SOCKET(i);
                        clnt_sockets.erase(
                            std::remove(clnt_sockets.begin(), clnt_sockets.end(), i),
                            clnt_sockets.end());
                        sessionKeys.erase(i);
                        peerRSAKeys.erase(i);
                        std::cout << "Closed client: " << i << std::endl;
                        if (i == max_fd)
                        {
                            while (FD_ISSET(max_fd, &reads) == false && max_fd > serv_sock)
                                max_fd--;
                        }
                        continue;
                    }
                    std::string received(buffer, str_len);
                    if (sessionKeys.find(i) == sessionKeys.end())
                    {
                        std::string key_exchange_prefix = "KEY_EXCHANGE|";
                        if (received.compare(0, key_exchange_prefix.length(), key_exchange_prefix) == 0)
                        {
                            try
                            {
                                std::vector<std::string> parts;
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
                                mpz_class client_e = crypto.hexTompz_class(parts[1]);
                                mpz_class client_n = crypto.hexTompz_class(parts[2]);
                                mpz_class client_dh_public = crypto.hexTompz_class(parts[3]);
                                mpz_class client_signature = crypto.hexTompz_class(parts[4]);
                                crypto.setPeerRSAKey(client_e, client_n);
                                bool is_valid = crypto.verifySignature(client_dh_public, client_signature);
                                if (!is_valid)
                                {
                                    throw std::runtime_error("Signature verification failed");
                                }
                                mpz_class shared_secret = crypto.computeSharedSecret(client_dh_public);
                                sessionKeys[i] = shared_secret;
                                size_t count = (mpz_sizeinbase(shared_secret.get_mpz_t(), 2) + 7) / 8;
                                std::vector<unsigned char> secret_bytes(count);
                                size_t written;
                                mpz_export(secret_bytes.data(), &written, 1, 1, 1, 0, shared_secret.get_mpz_t());
                                std::vector<uint8_t> full = sha256.hash(secret_bytes.data(), secret_bytes.size());
                                aesKeys[i] = std::vector<uint8_t>(full.begin(), full.begin() + 16);
                                for (socket_t fd : clnt_sockets)
                                {
                                    std::cout << "Session key for " << fd << ": " << sessionKeys[fd] << std::endl;
                                }
                                std::string confirm = "KEY_EXCHANGE_COMPLETE";
                                send(i, confirm.c_str(), confirm.length(), 0);
                            }
                            catch (const std::exception &e)
                            {
                                std::cerr << "Key exchange error: " << e.what() << std::endl;
                                FD_CLR(i, &reads);
                                CLOSE_SOCKET(i);
                                clnt_sockets.erase(
                                    std::remove(clnt_sockets.begin(), clnt_sockets.end(), i),
                                    clnt_sockets.end());
                                sessionKeys.erase(i);
                                peerRSAKeys.erase(i);
                                continue;
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            std::string decrypted_str = crypto.decryptAES(received, aesKeys[i]);
                            for (socket_t fd : clnt_sockets)
                            {
                                if (fd != serv_sock)
                                {
                                    if (sessionKeys.find(fd) != sessionKeys.end())
                                    {
                                        std::string encrypted_str = crypto.encryptAES(decrypted_str, aesKeys[fd]);
                                        send(fd, encrypted_str.c_str(), encrypted_str.length(), 0);
                                    }
                                }
                            }
                        }
                        catch (const std::exception &e)
                        {
                            std::cerr << "Message process error: " << e.what() << std::endl;
                            FD_CLR(i, &reads);
                            CLOSE_SOCKET(i);
                            clnt_sockets.erase(
                                std::remove(clnt_sockets.begin(), clnt_sockets.end(), i),
                                clnt_sockets.end());
                            sessionKeys.erase(i);
                            peerRSAKeys.erase(i);
                            aesKeys.erase(i);
                            continue;
                        }
                    }
                }
            }
        }
    }
    for (socket_t sock : clnt_sockets)
    {
        if (sock != serv_sock)
        {
            CLOSE_SOCKET(sock);
        }
    }
    CLOSE_SOCKET(serv_sock);
}