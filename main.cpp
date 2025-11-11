#include<iostream>
#include<string>
#include<cstring>
#include<map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

struct DnsHeader {
    u_short id; 
    short flags; 
    u_short qdCount, anCount, nsCount, arCount;
};

enum QType {
    A = 1,
    AAAA = 28,
    PTR = 12,
    SOA = 6,
    CNAME = 5
};

static map<string, QType> qtypes = {
    {"a", A}, {"aaaa", AAAA}, {"ptr", PTR}, {"soa", SOA}, {"cname", CNAME}
};

struct QuerySection {
    char qName[255];
    QType qType;
    u_short qClass;
};

enum OpCode {
    standard = 0,
    inverse = 1,
    server_status = 2
};

struct DnsRequest {
    DnsHeader header;
    QuerySection query;
    DnsRequest(u_short id, OpCode opcode, string host, QType qType) {
        header = {id, (short)(0 << 15 | opcode << 14 | 1 << 8), 1};
        query = {"", qType, 1};
        memcpy(&query.qName, host.c_str(), min((int)host.size(), 255));
    }
};

struct AnswerSection {
    char name[255];
    QType type; 
    u_short klass;
    int ttl;
    u_short rdLength;
    char rData[65535];
};

struct DnsResponse {
    DnsHeader header;
    QuerySection query;
    AnswerSection answer;
};

void printUsage() {
    // TODO
}

int main (int argc, char** argv) {
    QType qType = A;
    u_int timeout = 1000, port = 53;
    bool verbose;
    string host = "8.8.8.8";
    try {
        for (u_int i = 0; i < argc; i++) {
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
            } else {
                printUsage();
                return -1;
            }
        }
    } catch (exception e) {
        printUsage();
        return -1;
    }
    int client = socket(AF_INET, SOCK_DGRAM,0);
    sockaddr_in serverAddress {AF_INET, htons(port)};
    inet_aton(host.c_str(), &serverAddress.sin_addr);
    u_int serverAddressSize = sizeof(sockaddr_in);
    DnsRequest request = DnsRequest((u_short)1, (OpCode)0, host, qType);
    sendto(client, &request, sizeof(DnsRequest), 0, (sockaddr*)&serverAddress, serverAddressSize);
    DnsResponse response;
    recvfrom(client, &response, sizeof(DnsResponse), 0, (sockaddr*)&serverAddress, &serverAddressSize);
    cout << response.answer.rData << endl;
    close(client);
    return 0;
}