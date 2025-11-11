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
    char qName[255];
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
        query = {"", htons(qType), htons(1)}; // TODO htons
        string encodedHost = encodeName(host);
        memcpy(&query.qName, encodedHost.c_str(), min((int)encodedHost.length(), 255));
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AnswerSection {
    char name[255];
    u_short type, klass;
    u_int ttl;
    u_short rdLength;
    char rData[65535];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct DnsResponse {
    DnsHeader header;
    QuerySection query;
    AnswerSection answer;
};
#pragma pack(pop)

string getPrettyPayload(char* payload) {
    string payloadString = string(payload);
    int terminatorPos = payloadString.find("\0");
    return payloadString.substr(0, terminatorPos + 1);
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
    string prettyPayload = getPrettyPayload(request.query.qName);
    u_int offset = 0, bytesToSend = sizeof(DnsRequest) - 255 + prettyPayload.size();
    memcpy(requestBuffer, &request.header, sizeof(DnsHeader));
    offset += sizeof(request.header);
    memcpy(requestBuffer + offset, prettyPayload.c_str(), prettyPayload.size());
    offset += prettyPayload.size();
    memcpy(requestBuffer + offset, &request.query.qType, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(requestBuffer + offset, &request.query.qClass, sizeof(u_short));
    sendto(client, requestBuffer, bytesToSend, 0, (sockaddr*)&serverAddress, serverAddressSize);

    DnsResponse response;
    char responseBuffer[sizeof(DnsResponse)];
    int bytesReceived = recvfrom(client, responseBuffer, sizeof(DnsResponse), 0, (sockaddr*)&serverAddress, &serverAddressSize);
    offset = 0;
    memcpy(&response, responseBuffer, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);
    u_int qNameEnd; // TODO: Find '\0'
    memcpy(&response.query.qName, responseBuffer + offset, qNameEnd + 1);
    offset += qNameEnd + 1;
    memcpy(&response.query + qNameEnd + 1, responseBuffer + offset, 2 * sizeof(u_short));
    offset += 2 * sizeof(u_short);
    u_int nameEnd; // TODO: find '\0'
    memcpy(&response.answer, responseBuffer + offset, nameEnd + 1);
    memcpy(&response.answer + nameEnd + 1, responseBuffer + offset, 10);
    offset += 10;
    u_int rDataEnd; // TODO: find '\0'
    memcpy(&response.answer + 10, responseBuffer + offset, rDataEnd + 1);
    cout << response.answer.rData << endl;

    close(client);
    return 0;
}