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

static const u_int BUFFER_SIZE = 1024;

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
    vector<QuerySection> queries;
    DnsRequest(const u_short id, const OpCode opcode, const string host, const QType qType) {
        header = {id, (u_short)(opcode << 14 | 1 << 8), 1};
        queries = {{host, qType, 1}};
    }
    DnsRequest(const DnsHeader header, const vector<QuerySection> queries): header(header), queries(queries) { }
    DnsRequest hton() {
        transform(queries.begin(), queries.end(), queries.begin(), [](QuerySection& query){return query.hton();});
        return DnsRequest(header.hton(), queries);
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
    vector<QuerySection> queries;
    vector<AnswerSection> answers;
    DnsResponse ntoh() {
        transform(queries.begin(), queries.end(), queries.begin(), [](QuerySection& query){return query.ntoh();});
        transform(answers.begin(), answers.end(), answers.begin(), [](AnswerSection& answer){return answer.ntoh();});
        return {header.ntoh(), queries, answers};
    }
};

auto parseFlags(const u_short flags) {
    return tuple(
       flags >> 15,
       (flags >> 11) & 0x0F,
       (flags >> 10) & 0x1,
       (flags >> 9) & 0x1,
       (flags >> 8) & 0x1,
       (flags >> 7) & 0x1,
       (flags >> 4) & 0x07,
       flags & 0x0F
    );
}

string parseName(const char* responseBuffer, u_int& offset, const char* packet_start = nullptr) {
    string name;
    bool first = true;
    while (true) {
        u_char len = responseBuffer[offset++];
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) {
            if (packet_start == nullptr) packet_start = responseBuffer;
            int ptr = ((len & 0x3F) << 8) | responseBuffer[offset++];
            int saved_offset = offset;
            offset = ptr;
            string part = parseName(responseBuffer, offset, packet_start);
            if (!first) name += '.';
            name += part;
            offset = saved_offset;
            break;
        }

        if (!first) name += '.';
        name.append(responseBuffer + offset, len);
        offset += len;
        first = false;
    }
    return name;
}

string parsePayload(
    const char* responseBuffer,
    const QType qType,
    u_int& offset,
    const u_int rdLength
) {
    switch(qType) {
        case A: {
            in_addr addr;
            memcpy(&addr, responseBuffer + offset, rdLength);
            offset += rdLength;
            char addrChar[INET_ADDRSTRLEN];
            const char* address = inet_ntop(AF_INET, &addr.s_addr, addrChar, INET_ADDRSTRLEN);
            return string(address);
        }
        case AAAA: {
            in6_addr addr;
            memcpy(&addr, responseBuffer + offset, rdLength);
            offset += rdLength;
            char addrChar[INET6_ADDRSTRLEN];
            const char* address = inet_ntop(AF_INET6, &addr, addrChar, INET6_ADDRSTRLEN);
            return string(address);
        }
        case PTR:
        case CNAME:
            return parseName(responseBuffer, offset);
        default:
            offset += rdLength;
            return "Неизвестный тип записи";
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

void print(const DnsHeader& header) {
    cout << "ID: " << header.id << endl;
    auto [qr, opcode, aa, tc, rd, ra, z, rcode] = parseFlags(header.flags);
    cout << "QR: " << qr<< endl;
    cout << "OPCODE: " << opcode << endl;
    cout << "AA: " << aa << endl;
    cout << "TC: " << tc << endl;
    cout << "RD: " << rd << endl;
    cout << "RA: " << ra << endl;
    cout << "Z: " << z << endl;
    cout << "RCODE: " << rcode << endl;
    cout << "QDCOUNT: " << header.qdCount << endl;
    cout << "ANCOUNT: " << header.anCount << endl;
    cout << "NSCOUNT: " << header.nsCount << endl;
    cout << "ARCOUNT: " << header.arCount << endl;
}

void delimeter() {
    cout << "----------------------------------" << endl;
}

void print(const QuerySection& query) {
    cout << "QNAME: " << query.qName << endl;
    cout << "QTYPE: " << query.qType << endl;
    cout << "QCLASS: " << query.qClass << endl;
}

void print(const AnswerSection& answer) {
    cout << "NAME: " << answer.name << endl;
    cout << "TYPE: " << answer.type << endl;
    cout << "TTL: " << answer.ttl << endl;
    cout << "RDLENGTH: " << answer.rdLength << endl;
}

void print(const DnsRequest& request) {
    cout << "Запрос:" << endl;
    delimeter();
    print(request.header);
    delimeter();
    for (const QuerySection& query : request.queries) {
        print(query);
        delimeter();
    }
}

void print(const DnsResponse& response) {
    cout << "Ответ:" << endl;
    delimeter();
    print(response.header);
    delimeter();
    for (const QuerySection& query : response.queries) {
        print(query);
        delimeter();
    }
    for (const AnswerSection& answer : response.answers) {
        print(answer);
        delimeter();
    }
}

void printUsage(const char* program) {
    cout << "Использование: " << program << endl;
    cout << " -h, --host\t" << "имя для поиска" << endl;
    cout << "[-q, --qtype\t" << "тип записи]" << endl;
    cout << "[-v, --verbose\t" << "подробный вывод]" << endl;
    cout << "[-p, --port\t" << "порт DNS-сервера]" << endl;
    cout << "[-s, --server\t" << "ip-адрес DNS-сервера]" << endl;
    cout << "[-t, --timeout\t" << "время таймаута, мс.]" << endl;
}

DnsResponse requestName(
    DnsRequest& request,
    const int client,
    const sockaddr_in* serverAddress
) {
    request = request.hton();

    char requestBuffer[BUFFER_SIZE];

    u_int offset = 0;
    memcpy(requestBuffer, &request.header, sizeof(DnsHeader));
    offset += sizeof(request.header);

    for (const QuerySection& query : request.queries) {
        string payload = query.qName;
        memcpy(requestBuffer + offset, payload.data(), payload.size());
        offset += payload.size();
        memcpy(requestBuffer + offset, &query.qType, sizeof(u_short));
        offset += sizeof(u_short);
        memcpy(requestBuffer + offset, &query.qClass, sizeof(u_short));
        offset += sizeof(u_short);
    }

    u_int serverAddressSize = sizeof(sockaddr_in);

    sendto(client, requestBuffer, offset, 0, (sockaddr*)serverAddress, serverAddressSize);

    DnsResponse response;
    char responseBuffer[BUFFER_SIZE];

    int bytesReceived = recvfrom(client, responseBuffer, BUFFER_SIZE, 0, (sockaddr*)serverAddress, &serverAddressSize);
    offset = 0;

    memcpy(&response.header, responseBuffer, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);

    response.queries = vector<QuerySection>(ntohs(response.header.qdCount));

    for (QuerySection& query : response.queries) {
        query.qName = parseName(responseBuffer, offset);
        memcpy(&query.qType, responseBuffer + offset, sizeof(u_short));
        offset += sizeof(u_short);
        memcpy(&query.qClass, responseBuffer + offset, sizeof(u_short));
        offset += sizeof(u_short);
    }

    response.answers = vector<AnswerSection>(ntohs(response.header.anCount));

    for (AnswerSection& answer : response.answers) {
        answer.name = parseName(responseBuffer, offset);
        memcpy(&answer.type, responseBuffer + offset, sizeof(u_short));
        offset += sizeof(u_short);
        memcpy(&answer.klass, responseBuffer + offset, sizeof(u_short));
        offset += sizeof(u_short);
        memcpy(&answer.ttl, responseBuffer + offset, sizeof(u_int));
        offset += sizeof(u_int);
        memcpy(&answer.rdLength, responseBuffer + offset, sizeof(u_short));
        offset += sizeof(u_short);
        answer.rData = parsePayload(responseBuffer, (QType) ntohs(answer.type), offset, ntohs(answer.rdLength));
    }
    
    response = response.ntoh();

    return response;
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
                printUsage(argv[0]);
                return -1;
            }
        }
        if (host.empty()) {
            printUsage(argv[0]);
            return -1;
        }
    } catch (exception e) {
        printUsage(argv[0]);
        return -1;
    }
    int client = socket(AF_INET, SOCK_DGRAM,0);
    sockaddr_in serverAddress {AF_INET, htons(port)};
    inet_aton(serverHost.c_str(), &serverAddress.sin_addr);
    u_int serverAddressSize = sizeof(sockaddr_in);

    DnsRequest request = DnsRequest((u_short)1, (OpCode)0, host, qType);
    
    for (QuerySection& query : request.queries) {
        if (qType == PTR) {
            if (query.qName.find(".") < string::npos) {
                query.qName = getInAddrArpa(query.qName);
            }
            else {
                query.qName = getInAddr6Arpa(query.qName);
            }
        }
    }
    
    if (verbose) {
        print(request);
    }
    
    DnsResponse response = requestName(request, client, &serverAddress);

    if (verbose) {
        print(response);
    } else {
        for (const AnswerSection& answer : response.answers) {
            cout << answer.rData << endl;
        }
    }

    close(client);
    return 0;
}