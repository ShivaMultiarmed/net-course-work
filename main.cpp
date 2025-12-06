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

#pragma pack(push, 1)
struct IpHeader {
    u_char versionAndIhl, tos;
    u_short length, id, flagsAndOffset;
    u_char ttl, protocol;
    u_short checkSum;
    u_int source, destination;
    IpHeader hton() {
        return { versionAndIhl, tos, htons(length), htons(id), 
            htons(flagsAndOffset), ttl, protocol, checkSum, 
            htonl(source), htonl(destination) };
    }
}; 
#pragma pack(pop)

#pragma pack(push, 1)
struct UdpHeader {
    u_short source, destination, length, checkSum;
    UdpHeader hton() {
        return {htons(source), htons(destination), htons(length), checkSum};
    }
};
#pragma pack(pop)

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

enum QType: u_short {
    A = 1,
    NS = 2,
    CNAME = 5,
    PTR = 12,
    AAAA = 28
}; 

static const map<string, QType> qtypes = {
    {"a", A}, {"aaaa", AAAA}, {"ptr", PTR}, {"cname", CNAME}, {"ns", NS}
};

struct DnsHeader {
    u_short id, flags, qdCount, anCount, nsCount, arCount;
    DnsHeader hton() {
        return {htons(id), htons(flags), htons(qdCount), htons(anCount), htons(nsCount), htons(arCount)};
    }
    DnsHeader ntoh() {
        return {ntohs(id), ntohs(flags), ntohs(qdCount), ntohs(anCount), ntohs(nsCount), ntohs(arCount)};
    }
};

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
        vector<QuerySection> networkOrderQuries(queries.size());
        transform(queries.begin(), queries.end(), networkOrderQuries.begin(), [](QuerySection& query){return query.hton();});
        return DnsRequest(header.hton(), networkOrderQuries);
    }
    u_short size() const {
        u_short s = sizeof(header);
        for (const QuerySection& query : queries) {
            s += query.qName.size() + 2 * sizeof(u_short);
        }
        return s;
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
    vector<AnswerSection> answers, authorities, additionals;
    DnsResponse ntoh() {
        vector<QuerySection> hostOrderedQueries(queries.size());
        vector<AnswerSection> hostOrderedAnswers(answers.size()), hostOrdersAuthorities(authorities.size()), hostOrderedAdditionals(additionals.size());
        transform(queries.begin(), queries.end(), hostOrderedQueries.begin(), [](QuerySection& query){return query.ntoh();});
        transform(answers.begin(), answers.end(), hostOrderedAnswers.begin(), [](AnswerSection& answer){return answer.ntoh();});
        transform(authorities.begin(), authorities.end(), hostOrdersAuthorities.begin(), [](AnswerSection& authority){return authority.ntoh();});
        transform(additionals.begin(), additionals.end(), hostOrderedAdditionals.begin(), [](AnswerSection& additional){return additional.ntoh();});
        return {header.ntoh(), hostOrderedQueries, hostOrderedAnswers, hostOrdersAuthorities, hostOrderedAdditionals};
    }
};

void addMod16(u_long& a, u_long b = 0) {
    a += b;
    while(a >> 16) {
        a = (a >> 16) + (a & 0xFFFF);
    }
}

u_short evaluateUdpCheckSum(
    const u_int srcIp, 
    const u_int dstIp,
    const UdpHeader& udp,
    const DnsRequest& request
) {
    u_long result = 0;
    addMod16(result, srcIp >> 16);
    addMod16(result, srcIp & 0xFFFF);
    addMod16(result, dstIp >> 16);
    addMod16(result, dstIp & 0xFFFF);
    addMod16(result, 0x0011);
    addMod16(result, sizeof(UdpHeader) + (u_short) request.size());
    u_short* udpFields = (u_short*) &udp;
    for (u_int i = 0; i < 4; i++) {
        addMod16(result, udpFields[i]);
    }
    u_short* dnsHeaderFields = (u_short*) &request.header;
    for (u_int i = 0; i < 4; i++) {
        addMod16(result, dnsHeaderFields[i]);
    }
    char tempBuffer[1024] = {0};
    u_int offset = 0;
    for (const QuerySection& query : request.queries) {
        memcpy(tempBuffer + offset, query.qName.data(), query.qName.size());
        offset += query.qName.size();
        memcpy(tempBuffer + offset, &query.qType, sizeof(u_short));
        offset += sizeof(u_short);
        memcpy(tempBuffer + offset, &query.qClass, sizeof(u_short));
        offset += sizeof(u_short);
    }
    u_short* words = (u_short*) tempBuffer;
    for (u_int i = 0; i < offset / 2; i++) {
        addMod16(result, words[i]);
    }
    if (request.size() % 2 != 0) {
        addMod16(result, tempBuffer[offset - 1] << 8);
    }
    cout << result << endl;
    cout << (u_short) result << endl;
    cout << (u_short)~((u_short) result) << endl;
    return ~((u_short)result); 
}

/*u_short evaluateIpv4CheckSum(const IpHeader& ip) {
    u_long result = 0;
    u_short * header = (u_short *) &ip;
    for (u_char i = 0; i < 10; i++) {
        result += header[i];
    }
    while (result >> 16) {
        result = result >> 16 + result & 0xFFFF;
    }
    return (u_long)~result;
}*/

u_short evaluateIpv4CheckSum(const IpHeader& ip) {
    u_long result = 0;
    u_short * header = (u_short *) &ip;
    for (u_char i = 0; i < 10; i++) {
        addMod16(result, header[i]);
    }
    return ~result;
}

string parseName(
    const char* responseBuffer, 
    u_int& offset, 
    const char* packet_start = nullptr
) {
    string name;
    bool first = true;
    while (true) {
        u_char len = responseBuffer[offset++];
        if (len == 0) {
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (packet_start == nullptr) {
                packet_start = responseBuffer;
            }
            int ptr = ((len & 0x3F) << 8) | responseBuffer[offset++];
            int saved_offset = offset;
            offset = ptr;
            string part = parseName(responseBuffer, offset, packet_start);
            if (!first) { 
                name += '.';
            }
            name += part;
            offset = saved_offset;
            break;
        }

        if (!first) {
            name += '.';
        }
        name.append(responseBuffer + offset, len);
        offset += len;
        if (first) {
            first = false;
        }
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
        case NS:
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

void parseAnswer(
    AnswerSection& answer, 
    const char* responseBuffer, 
    u_int& offset
) {
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

DnsResponse requestData(
    DnsRequest& request,
    const int client,
    const string sourceIp,
    const string destinationIp,
    const sockaddr_in* serverAddress
) {
    char requestBuffer[BUFFER_SIZE];
    u_int offset = 0;

    in_addr srcIp, dstIp;
    inet_aton(sourceIp.c_str(), &srcIp);
    inet_aton(destinationIp.c_str(), &dstIp);

    DnsRequest requestCopy = request.hton();

    IpHeader ip = {(4 << 4) | (sizeof(IpHeader) / 4), 0x00, requestCopy.size() + sizeof(UdpHeader) + sizeof(IpHeader), 1, 0, 128, 17, 0, ntohl(srcIp.s_addr), ntohl(dstIp.s_addr)};
    ip = ip.hton();
    ip.checkSum = evaluateIpv4CheckSum(ip);
    memcpy(requestBuffer, &ip, sizeof(IpHeader));
    offset += sizeof(IpHeader);
    
    UdpHeader udp = {5000, 53, sizeof(UdpHeader) + requestCopy.size(), 0};
    // udp.checkSum = evaluateUdpCheckSum(ntohl(srcIp.s_addr), ntohl(dstIp.s_addr), udp, request);
    udp = udp.hton();
    memcpy(requestBuffer + offset, &udp, sizeof(UdpHeader));
    offset += sizeof(UdpHeader);

    request = request.hton();
    memcpy(requestBuffer + offset, &request.header, sizeof(DnsHeader));
    offset += sizeof(request.header);
    for (const QuerySection& query : request.queries) {
        memcpy(requestBuffer + offset, query.qName.data(), query.qName.size());
        offset += query.qName.size();
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
    
    u_int ipHeaderLength = (((u_char *)responseBuffer)[0] & 0x0F) * 4;
    cout << ipHeaderLength << endl;
    offset = ipHeaderLength + sizeof(UdpHeader);

    memcpy(&response.header, responseBuffer + offset, sizeof(DnsHeader));
    offset += sizeof(DnsHeader);

    cout << bytesReceived << endl;
    cout << responseBuffer << endl;

    auto h = response.header.ntoh();
    cout << h.qdCount << endl;
    cout << h.anCount << endl;
    cout << h.nsCount << endl;
    cout << h.arCount << endl;

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
        parseAnswer(answer, responseBuffer, offset);
    }

    response.authorities = vector<AnswerSection>(ntohs(response.header.nsCount));

    for (AnswerSection& authority : response.authorities) {
        parseAnswer(authority, responseBuffer, offset);
    }

    response.additionals = vector<AnswerSection>(ntohs(response.header.arCount));

    for (AnswerSection& additional : response.additionals) {
        parseAnswer(additional, responseBuffer, offset);
    }
    
    response = response.ntoh();

    return response;
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
    cout << "RDATA: " << answer.rData << endl;
}

void print(const DnsRequest& request) {
    cout << "Запрос:" << endl;
    delimeter();
    print(request.header);
    delimeter();
    cout << "Секция запросов:" << endl;
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
    cout << "Секция запросов:" << endl;
    delimeter();
    for (const QuerySection& query : response.queries) {
        print(query);
        delimeter();
    }
    if (!response.answers.empty()) {
        cout << "Секция ответов" << endl;
        delimeter();
        for (const AnswerSection& answer : response.answers) {
            print(answer);
            delimeter();
        }
    } else {
        cout << "Ничего не найдено" << endl;
    }
    if (!response.authorities.empty()) {
        cout << "NS секция" << endl;
        delimeter();
        for (const AnswerSection& authority : response.authorities) {
            print(authority);
            delimeter();
        }
    }
    if (!response.additionals.empty()) {
        cout << "Дополнительно" << endl;
        delimeter();
        for (const AnswerSection& additional : response.additionals) {
            print(additional);
            delimeter();
        }
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

int main (int argc, char** argv) {
    QType qType = A;
    u_int timeout = 1000, port = 53;
    bool verbose = false;
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
    } catch (exception& e) {
        printUsage(argv[0]);
        return -1;
    }
    int client = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (client == -1) {
        perror("socket");
        return -2;
    }
    int one = 1;
    setsockopt(client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
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
    
    DnsResponse response = requestData(request, client, "192.168.1.11", serverHost, &serverAddress);

    if (verbose) {
        print(response);
    } else {
        if (!response.answers.empty()) {
            cout << "Секции ответов" << endl;
            delimeter();
            for (const AnswerSection& answer : response.answers) {
                cout << answer.rData << endl;
                delimeter();
            }
        } else {
            cout << "Ничего не найдено" << endl;
        }
    }

    close(client);
    return 0;
}