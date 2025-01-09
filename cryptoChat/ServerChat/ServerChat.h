// ServerChat.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once

#include <iostream>

// TODO: 在此处引用程序需要的其他标头。
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <vector>
#include <sstream>
#include <algorithm>
#include <map>
#include <cstring>
#include <iomanip>
#include "Crypto.h"

void server_epoll();
