#include<iostream>
#include<string>
#include<cstring>
#include<map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>

using namespace std;

#pragma pack(push, 1)
struct DnsHeader {
    u_short id, flags, qdCount, anCount, nsCount, arCount;
};
#pragma pack(pop)

enum QType: u_short {
    A = 1,
    AAAA = 28,
    PTR = 12,
    SOA = 6,
    CNAME = 5
};

static map<string, QType> qtypes = {
    {"a", A}, {"aaaa", AAAA}, {"ptr", PTR}, {"soa", SOA}, {"cname", CNAME}
};

#pragma pack(push, 1)
struct QuerySection {
    string qName;
    u_short qType, qClass;
};
#pragma pack(pop)

enum OpCode: u_char {
    standard = 0,
    inverse = 1,
    server_status = 2
};

string encodeName(string name) {
    vector<string> subStrings;
    while(!name.empty()) {
        int pos = name.find(".", 0), size = pos >= 0 ? pos : name.length();
        subStrings.push_back(name.substr(0, size));
        name = pos >= 0 ? name.substr(size + 1) : "";
    }
    for (string subString : subStrings) {
        name += static_cast<char>(subString.length());
        name.append(subString);
    }
    name += '\0';
    return name;
}

#pragma pack(push, 1)
struct DnsRequest {
    DnsHeader header;
    QuerySection query;
    DnsRequest(u_short id, OpCode opcode, string host, QType qType) {
        header = {htons(id), htons((short)(0 << 15 | opcode << 14 | 1 << 8)), htons(1)};
        string encodedHost = encodeName(host);
        query = {encodedHost, htons(qType), htons(1)};
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AnswerSection {
    string name;
    u_short type, klass;
    u_int ttl;
    u_short rdLength;
    string rData;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct DnsResponse {
    DnsHeader header;
    QuerySection query;
    AnswerSection answer;
};
#pragma pack(pop)

string getPrettyPayload(const string payload) {
    string payloadString;
    for (char ch : payload) {
        payloadString += ch;
        if (ch == '\0') break;
    }
    return payloadString;
}

string parseName(const char* buffer, u_int& offs) {
    string name;
    u_int offset = offs, originalOffset = offset;
    bool jumped = false; // флаг, что был jump через pointer
    const u_int MAX_JUMPS = 10; // защита от бесконечного цикла
    u_int jumps = 0;

    while (true) {
        if (jumps++ > MAX_JUMPS) break; // защита
        u_char len = buffer[offset];

        // конец имени
        if (len == 0) {
            if (!jumped) offset++; // сдвигаем только если не было pointer
            break;
        }

        // pointer compression: первые два бита = 11
        if ((len & 0xC0) == 0xC0) {
            u_char next = buffer[offset + 1];
            u_int pointer = ((len & 0x3F) << 8) | next;
            if (!jumped) offset += 2; // сдвигаем исходный offset один раз
            offset = pointer; // меняем offset на позицию pointer
            jumped = true;
            continue;
        }

        // обычная метка
        offset++;
        if (!name.empty()) name += '.';
        name.append(buffer + offset, len);
        offset += len;
    }

    // если был jump, вернуть исходный offset + 2 (pointer)
    if (jumped) {
        return {name, originalOffset + 2};
    }

    return name;
}

string parsePayload(const char* responseBuffer, u_int offset, u_int length) {
    string payload;
    memcpy(payload.data(), responseBuffer + offset, length);
    return payload;
}

void printUsage() {
    cout << "Incorrect usage" << endl;
    // TODO
}

int main (int argc, char** argv) {
    QType qType = A;
    u_int timeout = 1000, port = 53;
    bool verbose;
    string host, serverHost = "8.8.8.8";
    try {
        for (u_int i = 1; i < argc; i++) {
            string arg = string(argv[i]);
            if (arg == "--verbose" || arg == "-v") {
                verbose = true;
            } else if (arg == "--port" || arg == "-p") {
                port = stoi(argv[++i]);
            } else if (arg == "--timeout" || arg == "-t") {
                timeout = stoi(argv[++i]);
            } else if (arg == "--qtype" || arg == "-q") {
                qType = qtypes.at(string(argv[++i]));
            } else if (arg == "--host" || arg == "-h") {
                host = string(argv[++i]);
            } else if (arg == "--server" || arg == "-s") {
                serverHost = string(argv[++i]);
            } else {
                printUsage();
                return -1;
            }
        }
        if (host.empty()) {
            printUsage();
            return -1;
        }
    } catch (exception e) {
        printUsage();
        return -1;
    }
    int client = socket(AF_INET, SOCK_DGRAM,0);
    sockaddr_in serverAddress {AF_INET, htons(port)};
    inet_aton(serverHost.c_str(), &serverAddress.sin_addr);
    u_int serverAddressSize = sizeof(sockaddr_in);

    DnsRequest request = DnsRequest((u_short)1, (OpCode)0, host, qType);
    char requestBuffer[sizeof(DnsRequest)];
    string payload = request.query.qName;
    u_int offset = 0;
    memcpy(requestBuffer, &request.header, sizeof(DnsHeader));
    offset += sizeof(request.header);
    memcpy(requestBuffer + offset, payload.c_str(), payload.size());
    offset += payload.size();
    memcpy(requestBuffer + offset, &request.query.qType, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(requestBuffer + offset, &request.query.qClass, sizeof(u_short));
    offset += sizeof(u_short);
    sendto(client, requestBuffer, offset, 0, (sockaddr*)&serverAddress, serverAddressSize);

    DnsResponse response;
    char responseBuffer[sizeof(DnsResponse)];
    int bytesReceived = recvfrom(client, responseBuffer, sizeof(DnsResponse), 0, (sockaddr*)&serverAddress, &serverAddressSize);
    offset = 0;
    memcpy(&response.header, responseBuffer, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);
    response.query.qName = parseName(responseBuffer, offset);
    offset += response.query.qName.size();
    memcpy(&response.query.qType, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.query.qClass, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    response.answer.name = parseName(responseBuffer, offset);
    offset += response.answer.name.size();
    memcpy(&response.answer.type, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.answer.klass, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.answer.ttl, responseBuffer + offset, sizeof(u_int));
    offset += sizeof(u_int);
    memcpy(&response.answer.rdLength, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    response.answer.rData = parsePayload(responseBuffer, offset, response.answer.rdLength);
    cout << response.answer.rData << endl;
    for (u_int i = 0; i < 1024; i++) {
        printf("%02x", responseBuffer[i]);
    }
    close(client);
    return 0;
}