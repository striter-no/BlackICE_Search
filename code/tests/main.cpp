#include <Project/requests.hpp>
#include <Project/nlohjson.hpp>

#include <nmap/nmap.hpp>
#include <nmap/parse_result.hpp>

#include <utils/vector.hpp>
#include <utils/files.hpp>

using namespace nlohmann;

std::string getDomain(std::string ip){
    auto host = sys::execute("host " + ip);
    if (host.find("not found") == std::string::npos){
        auto domain = utils::str::strip(utils::vec::stripsplit(host).back(), '\n');
        domain.pop_back();
        return domain;
    }
    return "__empty";
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
        
        std::cout << "[LOG] New scan" << std::endl;
        
        std::string out = scaner.scan(
            "", "",
            1000,
            {80, 443},
            "15s"
        );
        
        std::cout << "[LOG] Scanned, parsing multiple results"<< std::endl;

        
        auto scans = parser.split_mult_results(out);
        
        std::cout << "[LOG] Parsed, found " + std::to_string(scans.size()) + " hosts"<< std::endl;
        
        std::vector<std::string> payload;

        for (int i = 0; i < scans.size(); i++){ auto &scan = scans[i]; 
            std::cout << "[NEW_SCAN " << i << '/' << scans.size() << "][PIPE] New scan... ";
            
            auto host = parser.parse(scan);
            std::cout << "Parsed... ";
            if (!host.online){
                std::cout << "Host not online ";
            }
            std::cout<<"\r";

            auto domain = getDomain(host.ip);
            auto has_https = hasHTTPs(host.ports);
            
            payload.push_back(
                host.ip + ' ' + domain + ' ' + (has_https ? "true" : "false")
            );

            if (i == scans.size() - 1){
                break;
            }
        }

        std::cout << std::endl << "[LOG] Parsed all" << std::endl;
        // char p;std::cin >> p;

        std::string ans = "";
        for (auto &payl: payload){
            ans += payl;
            ans += '\n';
            // std::cout << payl << std::endl << std::endl;
        }

        // req.payload = payload.dump();
        std::cout << "[LOG] Send it to server" << std::endl;
        req.payload = ans;
        auto answer = req.response().data;

        if (answer != "ok"){
            std::cout << "Returned \"" << answer << '"' << std::endl << std::endl;
        } else {
            std::cout << "[LOG] Server accepted!" << std::endl;
        }
    }

}
