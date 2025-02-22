#pragma once

#include <system/execute.hpp>
#include <utils/vector.hpp>

namespace nmap {

    enum TARGET_SPEC {
        TARGET_DEFAULT,
        TARGET_RANDOM
    };

    enum SCAN_TECHNIQUES{
        TCP_SYN,
        TCP_CONN,
        TCP_ACK,
        WIN,
        MAIMON,
        UDP,
        TCP_NULL,
        FIN,
        XMAS,
        SCTP_INIT,
        SCTP_COOKIE_ECHO,
        IP_PROT,
        FTP_BOUNCE
    };

    enum HOST_DISCOVERY{
        PING_SCAN,
        ALL_HOSTS_ONLINE,
        TCP_SYN_PORT,
        TCP_ACK_PORT,
        UDP_PORT,
        SCTP_PORT,
        ICMP_ECHO,
        ICMP_TIMESTAMP,
        ICMP_ADDRESS_MASK,
        // IP_PROT_PING,
        NO_DNS_RESOLVE,
        ALW_DNS_RESOLVE,
        TRACEROUTE
    };

    enum PORT_SPEC{
        PORT_RANGE,
        ALL_PORTS,
        FEWER,
        NO_RANDOM
    };

    enum SERVICE_DETECT{
        PROBE,
        TRY_ALL_PROBES,
        VER_TRACE
    };

    enum SCRIPT_SCAN{
        NO_SCRIPT, // None
        DEFAULT, // sC
        TRACE_SCRIPT, // script-trace
        // EXPOIT, // TODO: implement
        CUSTOM_VULNERS, // vulners
        CUSTOM_GEOLOC, // ip-geolocation-geoplugin
        // CUSTOM_SSH_AUTH_INFO, // ssh-auth-methods TODO --script-args="ssh.user=<username>"
        CUSTOM_AUTH_SPOOF, // auth-spoof
        CUSTOM_TOR_CHECK, // tor-consensus-checker
        CUSTOM_WHOIS_IP, // whois-ip
        CUSTOM_WHOIS_DOMEN // whois-domen
    };

    enum OS_DETECTION{
        ENABLED,
        DISABLED,
        AGGRESIVE
    };

    enum PERFORMANCE{
        DEFAULT_PERF,
        SPEED_0,
        SPEED_1,
        SPEED_2,
        SPEED_3,
        SPEED_4,
        SPEED_5
    };

    enum FIREWALL_SPOOFING{
        FRAGMENT_PACKETS,
        // DECOYS, TODO
        // SPOOF_SOURCE,
        // SPOOF_MAC,
        BAD_SUM
    };

    enum OUTPUT{
        CONSOLE,
        XML,
        NORMAL,
        VERBOSE,
        VERY_VERBOSE,
        PACKET_TRACE,
        ONLY_OPEN
    };

    class Nmap{

            std::string resolveTargetSpec(TARGET_SPEC val){
                switch(val){
                    case TARGET_SPEC::TARGET_RANDOM: return "iR";
                }
                return "";
            }

            std::string resolveScanTech(SCAN_TECHNIQUES val){
                switch(val){
                    case SCAN_TECHNIQUES::TCP_SYN:    return "sS";
                    case SCAN_TECHNIQUES::TCP_ACK:    return "sA";
                    case SCAN_TECHNIQUES::TCP_CONN:   return "sT";
                    case SCAN_TECHNIQUES::WIN:        return "sW";
                    case SCAN_TECHNIQUES::MAIMON:     return "sM";
                    case SCAN_TECHNIQUES::UDP:        return "sU";
                    case SCAN_TECHNIQUES::TCP_NULL:   return "sN";
                    case SCAN_TECHNIQUES::FIN:        return "sF";
                    case SCAN_TECHNIQUES::XMAS:       return "sX";
                    case SCAN_TECHNIQUES::IP_PROT:    return "sO";
                    case SCAN_TECHNIQUES::FTP_BOUNCE: return "b";
                    
                    case SCAN_TECHNIQUES::SCTP_COOKIE_ECHO: return "sY";
                    case SCAN_TECHNIQUES::SCTP_INIT:        return "sZ";
                }
                return "";
            }

            std::string resolveHostDisc(HOST_DISCOVERY val){
                switch(val){
                    case HOST_DISCOVERY::PING_SCAN:         return "sn";
                    case HOST_DISCOVERY::ALL_HOSTS_ONLINE:  return "Pn";
                    case HOST_DISCOVERY::TCP_SYN_PORT:      return "PS";
                    case HOST_DISCOVERY::TCP_ACK_PORT:      return "PA";
                    case HOST_DISCOVERY::UDP_PORT:          return "PU";
                    case HOST_DISCOVERY::SCTP_PORT:         return "PY";
                    case HOST_DISCOVERY::ICMP_ECHO:         return "PE";
                    case HOST_DISCOVERY::ICMP_TIMESTAMP:    return "PP";
                    case HOST_DISCOVERY::ICMP_ADDRESS_MASK: return "PM";
                    // case HOST_DISCOVERY::IP_PROT_PING:      return "";
                    case HOST_DISCOVERY::NO_DNS_RESOLVE:    return "n";
                    case HOST_DISCOVERY::ALW_DNS_RESOLVE:   return "R";
                    case HOST_DISCOVERY::TRACEROUTE:        return "traceroute";
                }
                return "";
            }

            std::string resolveServiceDet(SERVICE_DETECT val){
                switch(val){
                    case SERVICE_DETECT::PROBE: return "sV";
                    case SERVICE_DETECT::TRY_ALL_PROBES: return "-version-all";
                    case SERVICE_DETECT::VER_TRACE: return "-version-trace";
                }
                return "";
            }

            std::string resolvePortSpec(PORT_SPEC val){
                switch(val){
                    case PORT_SPEC::FEWER: return "F";
                    case PORT_SPEC::NO_RANDOM: return "r";
                    case PORT_SPEC::ALL_PORTS: return "p-";
                }
                return "";
            }

            std::string resolveScripts(SCRIPT_SCAN val){
                switch(val){
                    case SCRIPT_SCAN::NO_SCRIPT: return "";
                    case SCRIPT_SCAN::DEFAULT: return "sC";
                    case SCRIPT_SCAN::TRACE_SCRIPT: return "script-trace";
                    case SCRIPT_SCAN::CUSTOM_VULNERS: return "vuln";
                    case SCRIPT_SCAN::CUSTOM_GEOLOC: return "ip-geolocation-geoplugin";
                    case SCRIPT_SCAN::CUSTOM_AUTH_SPOOF: return "auth-spoof";
                    case SCRIPT_SCAN::CUSTOM_TOR_CHECK: return "tor-consensus-checker";
                    case SCRIPT_SCAN::CUSTOM_WHOIS_IP: return "whois-ip";
                    case SCRIPT_SCAN::CUSTOM_WHOIS_DOMEN: return "whois-domen";
                }

                return "";
            }

            std::string resolveOsDet(OS_DETECTION val){
                switch(val){
                    case OS_DETECTION::DISABLED: return "";
                    case OS_DETECTION::ENABLED: return "O";
                    case OS_DETECTION::AGGRESIVE: return "osscan-guess";
                }

                return "";
            }

            std::string resolvePerf(PERFORMANCE val){
                switch(val){
                    case PERFORMANCE::SPEED_0: return "T0";
                    case PERFORMANCE::SPEED_1: return "T1";
                    case PERFORMANCE::SPEED_2: return "T2";
                    case PERFORMANCE::SPEED_3: return "T3";
                    case PERFORMANCE::SPEED_4: return "T4";
                    case PERFORMANCE::SPEED_5: return "T5";
                }

                return "";
            }

            std::string resolveFirewallSpoof(FIREWALL_SPOOFING val){
                switch(val){
                    case FIREWALL_SPOOFING::FRAGMENT_PACKETS: return "f";
                    case FIREWALL_SPOOFING::BAD_SUM: return "badsum";
                }

                return "";
            }

            std::string resolveOutput(OUTPUT val){
                switch(val){
                    case OUTPUT::NORMAL: return "oN";
                    case OUTPUT::VERBOSE: return "v";
                    case OUTPUT::VERY_VERBOSE: return "vv";
                    case OUTPUT::XML: return "x";
                    case OUTPUT::PACKET_TRACE: return "-packet-trace";
                    case OUTPUT::ONLY_OPEN: return "-open";
                }

                return "";
            }

            std::vector<short> ports;

            std::vector<std::pair<SCAN_TECHNIQUES, bool>>   scanTechniques;
            std::vector<std::pair<HOST_DISCOVERY, bool>>    hostDiscovery;
            std::vector<std::pair<PORT_SPEC, bool>>         portSpecs;
            std::vector<std::pair<SERVICE_DETECT, bool>>    serviceDetection;
            std::vector<std::pair<SCRIPT_SCAN, bool>>       scriptsSpecs;
            std::vector<std::pair<FIREWALL_SPOOFING, bool>> firewallSpoofing;
            std::vector<std::pair<OUTPUT, bool>>            outputSpecs;

            OS_DETECTION osDetection = OS_DETECTION::DISABLED;
            TARGET_SPEC  targetSpec  =  TARGET_SPEC::TARGET_DEFAULT;
            PERFORMANCE  performance =  PERFORMANCE::DEFAULT_PERF;

        public:
            
            void option(SCAN_TECHNIQUES val, bool only_for_next = false){ scanTechniques.push_back({val, only_for_next});}
            void option(HOST_DISCOVERY val, bool only_for_next = false){ hostDiscovery.push_back({val, only_for_next});}
            void option(SERVICE_DETECT val, bool only_for_next = false){ serviceDetection.push_back({val, only_for_next});}
            void option(SCRIPT_SCAN val, bool only_for_next = false){ scriptsSpecs.push_back({val, only_for_next});}
            void option(FIREWALL_SPOOFING val, bool only_for_next = false){ firewallSpoofing.push_back({val, only_for_next});}
            void option(OUTPUT val, bool only_for_next = false){ outputSpecs.push_back({val, only_for_next});}
            void option(PORT_SPEC val, bool only_for_next = false){ portSpecs.push_back({val, only_for_next});}

            void option(OS_DETECTION val){ osDetection = val;}
            void option(PERFORMANCE val){ performance = val;}
            void option(TARGET_SPEC val){ targetSpec = val;}

            std::string scan(
                std::string address,
                std::string output_file = "",
                int num_of_random_ips = 1,
                std::vector<int> specified_ports = {},
                std::string max_timeout = "30m"
            ){
                
                std::string nmap_command = "nmap";
                std::vector<int> to_remove;
                std::vector<int> new_vec;

                to_remove = {}; new_vec = {};
                for (auto &val : scanTechniques){
                    if (val.second) to_remove.push_back((int)val.first);
                    std::string str_val = resolveScanTech(val.first);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }

                
                for (auto &val: scanTechniques){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                scanTechniques = utils::vec::processVector<int, std::pair<SCAN_TECHNIQUES, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<SCAN_TECHNIQUES, bool>((SCAN_TECHNIQUES)val, false);
                });

                
                to_remove = {}; new_vec = {};
                for (auto &val: hostDiscovery){
                    if (val.second) to_remove.push_back((int)val.first);
                    std::string str_val = resolveHostDisc(val.first);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }

                for (auto &val: hostDiscovery){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                hostDiscovery = utils::vec::processVector<int, std::pair<HOST_DISCOVERY, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<HOST_DISCOVERY, bool>((HOST_DISCOVERY)val, false);
                });
                
                to_remove = {}; new_vec = {};
                for (auto &val: portSpecs){
                    if (val.second) to_remove.push_back((int)val.first);
                    std::string str_val = resolvePortSpec(val.first);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }

                for (auto &val: portSpecs){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                portSpecs = utils::vec::processVector<int, std::pair<PORT_SPEC, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<PORT_SPEC, bool>((PORT_SPEC)val, false);
                });
                
                to_remove = {}; new_vec = {};
                for (auto &val: serviceDetection){
                    if (val.second) to_remove.push_back((int)val.first);
                    std::string str_val = resolveServiceDet(val.first);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }

                for (auto &val: serviceDetection){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                serviceDetection = utils::vec::processVector<int, std::pair<SERVICE_DETECT, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<SERVICE_DETECT, bool>((SERVICE_DETECT)val, false);
                });
                
                to_remove = {}; new_vec = {};
                for (auto &val: firewallSpoofing){
                    if (val.second) to_remove.push_back((int)val.first);
                    std::string str_val = resolveFirewallSpoof(val.first);
                    if (str_val.empty()) continue;
                    nmap_command += " -" + str_val;
                }

                for (auto &val: firewallSpoofing){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                firewallSpoofing = utils::vec::processVector<int, std::pair<FIREWALL_SPOOFING, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<FIREWALL_SPOOFING, bool>((FIREWALL_SPOOFING)val, false);
                });
                
                to_remove = {}; new_vec = {};
                for (auto &val: scriptsSpecs){
                    if (val.second) to_remove.push_back((int)val.first);
                    if (val.first == SCRIPT_SCAN::DEFAULT){
                        nmap_command += " -" + resolveScripts(val.first);
                        continue;
                    }

                    if (val.first == SCRIPT_SCAN::TRACE_SCRIPT){
                        nmap_command += "--" + resolveScripts(val.first);
                        continue;
                    }

                    std::string str_val = resolveScripts(val.first);
                    nmap_command += " --script=" + str_val;
                }

                for (auto &val: scriptsSpecs){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                scriptsSpecs = utils::vec::processVector<int, std::pair<SCRIPT_SCAN, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<SCRIPT_SCAN, bool>((SCRIPT_SCAN)val, false);
                });

                std::string str_val = resolveOsDet(osDetection);
                if (!str_val.empty()) nmap_command += " -" + str_val;

                str_val = resolvePerf(performance);
                if (!str_val.empty()) nmap_command += " -" + str_val;


                to_remove = {}; new_vec = {};
                for (auto &val: outputSpecs){
                    if (val.second) to_remove.push_back((int)val.first);
                    str_val = resolveOutput(val.first);
                    if (!str_val.empty()) nmap_command += " -" + str_val;
                    if (val.first != OUTPUT::CONSOLE && val.first != OUTPUT::ONLY_OPEN && val.first != OUTPUT::PACKET_TRACE)
                        nmap_command += " " + output_file;
                }

                for (auto &val: outputSpecs){
                    if (!utils::vec::count(to_remove, (int)val.first)) 
                        new_vec.push_back(val.first);
                }
                outputSpecs = utils::vec::processVector<int, std::pair<OUTPUT, bool>>(new_vec, [&](int inx, int val){
                    return std::make_pair<OUTPUT, bool>((OUTPUT)val, false);
                });

                if (!specified_ports.empty())
                    nmap_command += " -p";
                    
                for (auto &port: specified_ports){
                    nmap_command += std::to_string(port) + ',';
                }
                
                if (!specified_ports.empty())
                    nmap_command.pop_back();

                str_val = resolveTargetSpec(targetSpec);
                if (!str_val.empty()) 
                    nmap_command += " -" + str_val + " " + std::to_string(num_of_random_ips);
                else
                    nmap_command += " " + std::string(address.c_str());

                if (!max_timeout.empty())
                    nmap_command += " --host-timeout " + max_timeout;

                // sys::execute("mkdir -p ./tmp/nmap");
                std::cout << "Executing nmap command: " << nmap_command << std::endl;
                return sys::execute(nmap_command);
            }

            Nmap(){}
            ~Nmap(){}
    };
}