#include <Project/requests.hpp>
#include <Project/nlohjson.hpp>

#include <nmap/nmap.hpp>
#include <nmap/parse_result.hpp>

#include <utils/vector.hpp>
#include <utils/files.hpp>

using namespace nlohmann;

std::string getDomain(std::string ip){
    auto host = sys::execute("host " + ip, nullptr);
    if (host.find("not found") == std::string::npos){
        auto domen = utils::str::strip(utils::vec::stripsplit(host).back(), '\n');
        domen.pop_back();
        return domen;
    }
    return "";
}

bool hasHTTPs(std::vector<nmap::Port> &ports){
    for (auto &port: ports){
        if (port.service_name == "https")
            return true;
    }
    return false;
}

int main(){
    nmap::Nmap scaner;
    nmap::NmapParser parser;

    scaner.option( nmap::CONSOLE );
    scaner.option( nmap::SPEED_5 );

    scaner.option( nmap::TARGET_RANDOM );
    scaner.option( nmap::ONLY_OPEN     );

    requests::Request req;
    req.url = "http://192.168.31.100:8080/new_ip";
    req.method = requests::POST;
    while (true){
        std::cout << "[LOG] New scan\n";
        std::string out = scaner.scan(
            "", "",
            2000,
            {80, 443},
            "15s"
        );
        std::cout << "[LOG] Scanned, parsing multiple results\n";

        parser.nmap_output = out;

        auto scans = parser.split_mult_results();
        std::cout << "[LOG] Parsed, found " + std::to_string(scans.size()) + " hosts\n";
        for (auto &scan: scans){
            std::cout << "[NEW_SCAN][PIPE] New scan... ";
            parser.nmap_output = scan;
            parser.parse();
            std::cout << "Parsed... ";
            req.payload = json{
                    {"ip", parser.host.ip},
                    {"domain", getDomain(parser.host.ip)},
                    {"has-https", hasHTTPs(parser.host.ports)}
                }.dump();
            auto answer = req.response().data;
            std::cout << "Send to server... ";
            if (answer != "ok"){
                std::cout << req.payload << std::endl;
                std::cout << "Returned " << answer << std::endl << std::endl;
            }
            std::cout << "Ok!\r";
        }
    }

}