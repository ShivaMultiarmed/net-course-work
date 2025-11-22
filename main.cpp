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
#include <algorithm>
#include <sstream>
#include <iomanip>

using namespace std;

struct DnsHeader {
    u_short id, flags, qdCount, anCount, nsCount, arCount;
    DnsHeader hton() {
        return {htons(id), htons(flags), htons(qdCount), htons(anCount), htons(nsCount), htons(arCount)};
    }
    DnsHeader ntoh() {
        return {ntohs(id), ntohs(flags), ntohs(qdCount), ntohs(anCount), ntohs(nsCount), ntohs(arCount)};
    }
};

enum QType: u_short {
    A = 1,
    AAAA = 28,
    PTR = 12,
    CNAME = 5
}; 

static const map<string, QType> qtypes = {
    {"a", A}, {"aaaa", AAAA}, {"ptr", PTR}, {"cname", CNAME}
};

string encodeName(string name) {
    vector<string> subStrings;
    while(!name.empty()) {
        int pos = name.find("."), size = pos >= 0 ? pos : name.length();
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

struct QuerySection {
    string qName;
    u_short qType, qClass;
    QuerySection hton() {
        return {encodeName(qName), htons(qType), htons(qClass)};
    }
    QuerySection ntoh() {
        return {qName, ntohs(qType), ntohs(qClass)};
    }
};

enum OpCode: u_char {
    standard = 0,
    inverse = 1,
    server_status = 2
};

struct DnsRequest {
    DnsHeader header;
    QuerySection query;
    DnsRequest(const u_short id, const OpCode opcode, const string host, const QType qType) {
        header = {id, (u_short)(opcode << 14 | 1 << 8), 1};
        query = {host, qType, 1};
    }
    DnsRequest(const DnsHeader header, const QuerySection query): header(header), query(query) { }
    DnsRequest hton() {
        return DnsRequest(header.hton(), query.hton());
    }
};

struct AnswerSection {
    string name;
    u_short type, klass;
    u_int ttl;
    u_short rdLength;
    string rData;
    AnswerSection ntoh() {
        return {name, ntohs(type), ntohs(klass), ntohl(ttl), ntohs(rdLength), rData};
    }
};

struct DnsResponse {
    DnsHeader header;
    QuerySection query;
    AnswerSection answer;
    DnsResponse ntoh() {
        return {header.ntoh(), query.ntoh(), answer.ntoh()};
    }
};

string parseName(const char* buffer, u_int& offset, const char* packet_start = nullptr) {
    string name;
    bool first = true;
    while (true) {
        u_char len = buffer[offset++];
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) {
            if (packet_start == nullptr) packet_start = buffer;
            int ptr = ((len & 0x3F) << 8) | buffer[offset++];
            int saved_offset = offset;
            offset = ptr;
            string part = parseName(buffer, offset, packet_start);
            if (!first) name += '.';
            name += part;
            offset = saved_offset;
            break;
        }

        if (!first) name += '.';
        name.append(buffer + offset, len);
        offset += len;
        first = false;
    }
    return name;
}

string parsePayload(const char* responseBuffer, QType qType, u_int& offset, const u_int length) {
    switch(qType) {
        case A: {
            in_addr addr;
            memcpy(&addr, responseBuffer + offset, 4);
            offset += 4;
            char addrChar[INET_ADDRSTRLEN];
            const char* address = inet_ntop(AF_INET, &addr.s_addr, addrChar, INET_ADDRSTRLEN);
            return string(address);
        }
        case AAAA: {
            in6_addr addr;
            memcpy(&addr, responseBuffer + offset, 16);
            offset += 16;
            char addrChar[INET6_ADDRSTRLEN];
            const char* address = inet_ntop(AF_INET6, &addr, addrChar, INET6_ADDRSTRLEN);
            return string(address);
            break;
        }
        case PTR:
        case CNAME:
            return parseName(responseBuffer, offset);
        default:
            return "";
    }
}

string getInAddrArpa(string ip) {
    vector<string> ipSegments(4);
    for (u_int i = 0; i < 4; i++) {
        u_int dotPos = ip.find(".");
        ipSegments.at(i) = ip.substr(0, dotPos < string::npos ? dotPos : ip.size());
        ip = ip.replace(0, dotPos < string::npos ? dotPos + 1 : ip.size(), "");
    }
    reverse(ipSegments.begin(), ipSegments.end());
    string result;
    for (const string &segment : ipSegments) {
        result += segment + ".";
    }
    result += "in-addr.arpa";
    return result;
}

string getInAddr6Arpa(string ip){
    u_int groupCount = 1;
    for (char ch : ip) {
        if (ch == ':') {
            groupCount++;
        }
    }
    u_int compressionPos = ip.find("::");
    if (compressionPos < ip.size()) {
        u_int colonsToAdd = 8 - groupCount;
        for (u_int i = 0; i < colonsToAdd; i++) {
            ip.insert(compressionPos + 1, ":");
        }
    }
    u_int start = 0, end = 0;
    ip += ":";
    while(end < 8 * 4 + 8) {
        if (ip.at(end) == ':') {
            while (end - start < 4) {
                ip.insert(start, "0");
                end++;
            }
            end++;
            start = end;
        } else {
            end++;
        }
    }
    u_int colonPos = ip.find(":");
    while(colonPos < ip.size()) {
        ip = ip.replace(colonPos, 1, "");
        colonPos = ip.find(":");
    }
    reverse(ip.begin(), ip.end());
    for (u_int i = 0; i < 32; i++) {
        ip.insert(2 * i + 1, ".");
    }
    return ip + "ip6.arpa";
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
    
    char requestBuffer[1024];
    if (qType == PTR) {
        if (request.query.qName.find(".") < string::npos) {
            request.query.qName = getInAddrArpa(request.query.qName);
        }
        else {
            request.query.qName = getInAddr6Arpa(request.query.qName);
        }
    }
    request = request.hton();
    string payload = request.query.qName;
    u_int offset = 0;
    memcpy(requestBuffer, &request.header, sizeof(DnsHeader));
    offset += sizeof(request.header);
    memcpy(requestBuffer + offset, payload.data(), payload.size());
    offset += payload.size();
    memcpy(requestBuffer + offset, &request.query.qType, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(requestBuffer + offset, &request.query.qClass, sizeof(u_short));
    offset += sizeof(u_short);
    sendto(client, requestBuffer, offset, 0, (sockaddr*)&serverAddress, serverAddressSize);

    DnsResponse response;
    char responseBuffer[10 * 1024];
    int bytesReceived = recvfrom(client, responseBuffer, 1024, 0, (sockaddr*)&serverAddress, &serverAddressSize);
    offset = 0;
    memcpy(&response.header, responseBuffer, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);
    response.query.qName = parseName(responseBuffer, offset);
    memcpy(&response.query.qType, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.query.qClass, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    response.answer.name = parseName(responseBuffer, offset);
    memcpy(&response.answer.type, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.answer.klass, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    memcpy(&response.answer.ttl, responseBuffer + offset, sizeof(u_int));
    offset += sizeof(u_int);
    memcpy(&response.answer.rdLength, responseBuffer + offset, sizeof(u_short));
    offset += sizeof(u_short);
    response = response.ntoh();
    response.answer.rData = parsePayload(responseBuffer, (QType) response.query.qType, offset, response.answer.rdLength);
    offset += response.answer.rData.size();
    cout << response.answer.rData << endl;
    close(client);
    return 0;
}