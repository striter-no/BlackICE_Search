#pragma once

#include "nmap.hpp"
#include <memory>
#include <utils/vector.hpp>

namespace nmap {

    enum PORT_STATE{
        STATE_UNKNOWN,
        OPEN,
        CLOSED,
        FILTERED,
        OPEN_FILTERED,
        CLOSED_FILTERED
    };

    enum PORT_PROTOCOL{
        PROT_UNKNOWN,
        PROT_TCP,
        PROT_UDP,
        PROT_ICMP,
        PROT_SCTP,
        PROT_DCCP,
        PROT_FTP
    };

    struct Port{
        int port_number;
        PORT_STATE state;
        PORT_PROTOCOL protocol;

        std::string service_name;
        std::string service_version;
    };

    struct ScriptResult{
        std::vector<std::pair<std::string, std::string>> results;
    };

    struct CPE{
        std::string value;
    };

    struct Host{
        std::string ip;
        std::string os_name;
        std::string device_type;
        std::string os_details;
        int   network_distance = -1;
        int   opened_ports_num = -1;
        float host_latency = -1;
        
        std::vector<CPE>  cpes;
        std::vector<Port> ports;
        bool online = false;
    };

    class NmapParser {
        
            PORT_STATE resolvePortState(std::string state){
                if(state == "open") return PORT_STATE::OPEN;
                if(state == "closed") return PORT_STATE::CLOSED;
                if(state == "filtered") return PORT_STATE::FILTERED;
                if(state == "open|filtered") return PORT_STATE::OPEN_FILTERED;
                if(state == "closed|filtered") return PORT_STATE::CLOSED_FILTERED;
                return PORT_STATE::STATE_UNKNOWN;
            }

            PORT_PROTOCOL resolvePortProt(std::string protocol){
                if(protocol == "tcp") return PORT_PROTOCOL::PROT_TCP;
                if(protocol == "udp") return PORT_PROTOCOL::PROT_UDP;
                if(protocol == "icmp") return PORT_PROTOCOL::PROT_ICMP;
                if(protocol == "sctp") return PORT_PROTOCOL::PROT_SCTP;
                if(protocol == "dccp") return PORT_PROTOCOL::PROT_DCCP;
                if(protocol == "ftp") return PORT_PROTOCOL::PROT_FTP;
                return PORT_PROTOCOL::PROT_UNKNOWN;
            }

            std::string resolvePortState(PORT_STATE state){
                switch(state){
                    case PORT_STATE::OPEN: return "open";
                    case PORT_STATE::CLOSED: return "closed";
                    case PORT_STATE::FILTERED: return "filtered";
                    case PORT_STATE::OPEN_FILTERED: return "open|filtered";
                    case PORT_STATE::CLOSED_FILTERED: return "closed|filtered";
                    default: return "state_unknown";
                }
            }

            std::string resolvePortProt(PORT_PROTOCOL protocol){
                switch(protocol){
                    case PORT_PROTOCOL::PROT_TCP: return "tcp";
                    case PORT_PROTOCOL::PROT_UDP: return "udp";
                    case PORT_PROTOCOL::PROT_ICMP: return "icmp";
                    case PORT_PROTOCOL::PROT_SCTP: return "sctp";
                    case PORT_PROTOCOL::PROT_DCCP: return "dccp";
                    case PORT_PROTOCOL::PROT_FTP: return "ftp";
                    default: return "unknown_prot";
                }
            }

        public:

            std::vector<std::string> split_mult_results(std::string nmap_output){
                std::vector<std::string> results;
                auto lines = utils::vec::stripsplit(
                    nmap_output,
                    '\n'
                );

                std::string current_result = "";
                bool first_scan = true;
                for (auto &line : lines){
                    if (line.find("Nmap scan report") != std::string::npos && !first_scan){
                        results.push_back(current_result);
                        current_result = "";
                        // continue;
                    } else if (line.find("Nmap scan report") != std::string::npos){
                        first_scan = false;
                    }
                    // std::cout << " Line: " << line << std::endl;
                    current_result += line + "\n";
                }
                if (!current_result.empty())
                    results.push_back(current_result);

                return results;
            }

            Host parse(std::string nmap_output){
                Host host;
                auto lines = utils::vec::stripsplit(
                    nmap_output,
                    '\n'
                );

                bool port_section = false;
                bool script_section = false;

                int port_index  = -1;
                int state_index = -1;
                int service_index = -1;
                int version_index = -1;

                for (const auto& line : lines){
                    
                    if (line.find("Nmap scan report") != std::string::npos){
                        if (line.find('(') != std::string::npos){
                            for(int i = line.find('(')+1; i < line.size()-2; i++){
                                host.ip += line[i];
                            }
                        } else{
                            host.ip = utils::vec::split(line).back();
                        }
                    }

                    // std::cout << "Line: " << line << std::endl;
                    if (line.find("Host is down") != std::string::npos){
                        host.online = false;
                        return host;
                    }
                    if (line.find("Host is up") != std::string::npos){
                        auto str = utils::vec::stripsplit(line.substr(line.find("(")+1, line.find("latency")))[0];
                        str = str.substr(0, str.size()-1);
                        host.host_latency = std::stof(str);
                        host.online = true;
                    }
                    if (line.find("PORT") != std::string::npos){
                        port_section = true;

                        port_index = line.find('P');
                        state_index = line.find('S');
                        service_index = line.find('S', state_index+1);
                        version_index = line.find('V', line.find('V')+1);
                        
                        // std::cout << line << '\n' << port_index << " " << state_index << " " << service_index << " " << version_index << '\n';

                        continue;
                    }
                    if (port_section && 
                        (line.find('/') == std::string::npos || 
                         line.find("fingerprint") != std::string::npos ||
                         line.find("Info") != std::string::npos)
                    ){
                        
                        port_section = false;
                        host.opened_ports_num = 0;
                        for (auto &port: host.ports){
                            if (port.state != OPEN) continue;
                            host.opened_ports_num ++;
                        }
                        // continue;
                    }
                    if (port_section){
                        Port port;
                        if (port_index != -1){
                            std::string port_info;
                            int last_index = state_index == -1 ? line.size() : state_index;
                            for (int i = port_index; i < last_index; i++){
                                port_info += line[i];
                            }
                            port_info = utils::str::strip(port_info);
                            auto splitted = utils::vec::split(port_info, '/');
                            
                            // std::cout << "!![]" << splitted[0] << ' ' << line << std::endl;

                            try {port.port_number = std::stoi(splitted[0]);}
                            catch (const std::exception& e){continue;}
                            port.protocol = resolvePortProt(splitted[1]);
                        }

                        if (state_index != -1){
                            std::string state_info;
                            int last_index = service_index == -1 ? line.size() : service_index;
                            for (int i = state_index; i < last_index; i++){
                                state_info += line[i];
                            }
                            state_info = utils::str::strip(state_info);

                            port.state = resolvePortState(state_info);
                        }

                        if (service_index != -1){
                            std::string service_info;
                            int last_index = version_index == -1 ? line.size() : version_index;
                            for (int i = service_index; i < last_index; i++){
                                service_info += line[i];
                            }
                            service_info = utils::str::strip(service_info);
                            port.service_name = service_info;
                        }

                        if (version_index != -1){
                            std::string version_info;
                            int last_index = line.size();
                            for (int i = version_index; i < last_index; i++){
                                version_info += line[i];
                            }
                            version_info = utils::str::strip(version_info);
                            port.service_version = version_info;
                        }

                        host.ports.push_back(port);
                    }

                    if (line.find("hops") != std::string::npos){
                        
                        try{
                        host.network_distance = std::stoi(
                            utils::vec::split(line)[2]
                        );
                        } catch(const std::exception& e){continue;}
                    }

                    if (line.find("Running") != std::string::npos){
                        if (line.find("JUST") == std::string::npos)
                            host.os_name = line.substr(line.find("Running: ") + 9);
                        else
                            host.os_name = line.substr(line.find("Running") + 25);
                    }

                    if (line.find("OS details") != std::string::npos){
                        host.os_details = line.substr(line.find("OS details: ") + 12);
                    }

                    if (line.find("Device type:") != std::string::npos){
                        // std::cout << "DEVICE TYPE: "<< line << ' ' << line.substr(line.find("Device type: ") + 13) << std::endl;
                        host.device_type = line.substr(line.find("Device type: ") + 13);
                    }

                    if (line.find("cpe") != std::string::npos){
                        auto splitted = utils::vec::stripsplit(line);
                        for (auto& s : splitted){
                            if (s.find("cpe:/o:") != std::string::npos){
                                host.cpes.push_back({s});
                            }
                        }
                    }

                    if (line[0] == '|'){
                        ;
                    }
                }

                return host;
            }

            std::string stringify(Host host){
                std::string output = "";

                output += "Host info:";
                output += "\n--> IP: " + host.ip;
                output += "\n--> OS:";
                output += "\n    | --> Name:    " + host.os_name;
                output += "\n    | --> Details: " + host.os_details;
                output += "\n--> Device type:  " + host.device_type;
                output += "\n";
                output += "\n--> Network hops:     " + std::to_string(host.network_distance);
                output += "\n--> Host latency:     " + std::to_string(host.host_latency);
                output += "\n--> Opened ports num: " + std::to_string(host.opened_ports_num);
                output += "\n---------------------\n";
                output += "\n--> Scaned ports:";

                for (auto &port : host.ports){
                    output += "\n    | --> port " + std::to_string(port.port_number) + 
                              " | state: "  + resolvePortState(port.state) + 
                              " | service: " + port.service_name +
                              " | version: " + port.service_version;
                }

                output += "\n---------------------\n";
                output += "\n--> CPEs: ";
                for (auto &cpe : host.cpes){
                    output += "\n    | --> " + cpe.value;
                }

                return output;
            }

            NmapParser(){}
            ~NmapParser(){}
    };
}