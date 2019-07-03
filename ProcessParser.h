#include <algorithm>
#include <iostream>
#include <math.h>
#include <thread>
#include <chrono>
#include <iterator>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"


using namespace std;

class ProcessParser{
private:
    std::ifstream stream;
    public:
    static string getCmd(string pid);
    static vector<string> getPidList();
    static std::string getVmSize(string pid);
    static std::string getCpuPercent(string pid);
    static long int getSysUpTime();
    static std::string getProcUpTime(string pid);
    static string getProcUser(string pid);
    static vector<string> getSysCpuPercent(string coreNumber = "");
    static float getSysRamPercent();
    static string getSysKernelVersion();
    static int getNumberOfCores();
    static int getTotalThreads();
    static int getTotalNumberOfProcesses();
    static int getNumberOfRunningProcesses();
    static string getOSName();
    static std::string PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2);
    static bool isPidExisting(string pid);
    static float get_sys_active_cpu_time(vector<string> values) ;
    static float get_sys_idle_cpu_time(vector<string>values) ;
};

// TODO: Define all of the above functions below:
float ProcessParser::get_sys_active_cpu_time(vector<string> values)
{
        return (stof(values[S_USER]) +
                stof(values[S_NICE]) +
                stof(values[S_SYSTEM]) +
                stof(values[S_IRQ]) +
                stof(values[S_SOFTIRQ]) +
                stof(values[S_STEAL]) +
                stof(values[S_GUEST]) +
                stof(values[S_GUEST_NICE]));
}


float ProcessParser::get_sys_idle_cpu_time(vector<string>values)
{
        return (stof(values[S_IDLE]) + stof(values[S_IOWAIT]));
}


string ProcessParser::getCmd(string pid){ // returns the command for a given PID
    ifstream filestream;
    Util::getStream(Path::basePath()+pid+Path::cmdPath(), filestream); //opens this path
    //some PIDs might not have a cmdline so add a test for that.
    string line;
    getline(filestream, line);
    return line;

}


vector<string> ProcessParser::getPidList(){
    //PID is just the numbered directories under /proc
    vector<string> pids;

    DIR* dptr = opendir("/proc");
    struct dirent * dp;
    while ((dp = readdir(dptr)) != NULL) {
        if(dp->d_type != DT_DIR)
           continue;
        string name = string(dp->d_name); //convert from c-string to string
        //check to see if the names are all numbers
        if(for_each(name.begin(), name.end(), [](char const &c){if(isdigit(c)){return true;}else {return false;}})){
            pids.push_back(name);
        }
        else{
            continue;
        }
    }

    if(closedir(dptr))
        throw std::runtime_error(std::strerror(errno));
    return pids;
}


std::string ProcessParser::getVmSize(string pid){
    ifstream inFile;
    Util::getStream(Path::basePath()+pid+Path::statusPath(), inFile);
    string line;
    string key = "VmSize";
    int sizeinGb ;

    //find the line that starts with VmSize
    while(getline(inFile, line)){
        if(line.compare(0,key.length(), key) == 0){ //found the line that has "VmSize"
            break;
        }
    }

    //extract the VmSize number from the line
    stringstream ss;
    ss << line;
    string temp;
    while(!ss.eof()){
        ss >> temp;
        if(stringstream(temp) >> sizeinGb)
            break;
    }

    //convert to GB
    float res;
    res = sizeinGb/2048.00;

    return to_string(res);
}


std::string ProcessParser::getCpuPercent(string pid){ //required CPU usage info in /proc/pid/stat , man proc for more info
    vector<std::string> tokens;
    std::ifstream strm;
    string tok;
    Util::getStream(Path::basePath()+pid+"/"+Path::statPath(), strm);
    while(getline(strm , tok, ' ')){
        tokens.push_back(tok);
    }

    // acquiring relevant times for calculation of active occupation of CPU for selected process
    float utime = stof(ProcessParser::getProcUpTime(pid));
    float stime = stof(tokens[14]);
    float cutime = stof(tokens[15]);
    float cstime = stof(tokens[16]);
    float starttime = stof(tokens[21]);
    float uptime = ProcessParser::getSysUpTime();
    float freq = sysconf(_SC_CLK_TCK);
    float total_time = utime + stime + cutime + cstime;
    float seconds = uptime - (starttime/freq);
    float result = 100.0*((total_time/freq)/seconds);
    return to_string(result);

}


long int ProcessParser::getSysUpTime(){
    std::ifstream strm;
    Util::getStream(Path::basePath()+Path::upTimePath(), strm);

    vector<std::string> tokens;
    string tok;
    while(getline(strm , tok, ' ')){  //parsing string per line into tokens using the space as a delimiter
        tokens.push_back(tok);
    }

    long int sysup = stoi(tokens[0]);
    return sysup;
}


std::string ProcessParser::getProcUpTime(string pid){
    vector<std::string> tokens;
    std::ifstream strm;
    string tok;
    Util::getStream(Path::basePath()+pid+"/"+Path::statPath(), strm);

    while(getline(strm , tok, ' ')){  //parsing string per line into tokens using the space as a delimiter
        tokens.push_back(tok);
    }

    float uptime = stof(tokens[13])/sysconf(_SC_CLK_TCK);  //converting from clock ticks to seconds
    return std::to_string(uptime);
}


string ProcessParser::getProcUser(string pid){

    ifstream strm;
    Util::getStream(Path::basePath()+pid+Path::statusPath(), strm);
    string line;
    string key = "Uid:";
    string uid;
    while(getline(strm, line)){ //retrieve the actual UID
        stringstream ss(line);
        string token;
        ss >> token >> uid;
        if(token == key)
            break;
    }
    strm.close();

    //using the retrieved UID, now let's get the process user
    //this information is located in /etc/passwd
    Util::getStream("/etc/passwd", strm);
    string result = "x:"+uid;
    while(getline(strm, line)){
        if(line.find(result) != std::string::npos){
            result = line.substr(0, line.find(":"));
            return result;
        }
    }
    return ""; //return empty string if not found
}


vector<string> ProcessParser::getSysCpuPercent(string coreNumber){
    ifstream strm;
    Util::getStream(Path::basePath()+Path::statPath(), strm);
    string key = "cpu" + coreNumber;
    //vector<string> required_tokens;
    string line;
    while(getline(strm, line)){
        if(line.compare(0, key.size(),key) == 0){
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);
            // set of cpu data active and idle times;
            return values;
        }
    }

    return vector<string>(); //if given coreNumbered cpu not found
}


float ProcessParser::getSysRamPercent(){
    ifstream strm;
    Util::getStream(Path::basePath()+Path::memInfoPath(), strm);
    string line;

    string key1 = "MemAvailable:";
    string key2 = "MemFree:";
    string key3 = "Buffers:";

    float total, free, buffer;

    while(getline(strm, line)){

        if(total !=0 && free !=0)
            break;

        if(line.compare(0,key1.size(), key1) == 0){
            istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			total = stof(values[1]);
        }

        if(line.compare(0,key2.size(), key2) == 0){
            istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			free = stof(values[1]);
        }

        if(line.compare(0,key3.size(), key3) == 0){
            istringstream buf(line);
			istream_iterator<string> beg(buf), end;
			vector<string> values (beg, end);
			buffer = stof(values[1]);
        }
    }

    float result = 100.0*(1-(free/(total-buffer)));
    return result;
}


string ProcessParser::getSysKernelVersion(){
    ifstream strm;
    Util::getStream(Path::basePath()+Path::versionPath(), strm);
    string line;
    getline(strm, line);

    istringstream buf(line);
    istream_iterator<string> beg(buf), end;
    vector<string> values(beg, end);

    return values[2];
}


int ProcessParser::getNumberOfCores(){
    ifstream strm;
    Util::getStream(Path::basePath()+"cpuinfo", strm);
    string line;
    string key = "cpu cores";

    while(getline(strm, line)){
        if(line.compare(0, key.size(), key) == 0){
            istringstream buf(line);
            istream_iterator<string> beg(buf), end;
            vector<string> values(beg, end);

            return stoi(values[3]);
        }
     }
    return 0;
 }


int ProcessParser::getTotalThreads(){
    vector<string> list_pi = ProcessParser::getPidList();
    int thread_count = 0;
    for(string pid: list_pi){
        ifstream strm;

        Util::getStream(Path::basePath()+pid+ Path::statusPath(), strm);
        string line;
        string key= "Threads:";
        int thread = 0;
        string rand;
        while(getline(strm, line)){
            if(line.compare(0, key.size(), key) == 0){
                stringstream ss(line);
                ss >> rand >> thread;
                thread_count += thread;
            }
        }
        strm.close();
    }

    return thread_count;
}


int ProcessParser::getTotalNumberOfProcesses(){
    ifstream strm;
    Util::getStream(Path::basePath()+Path::statPath(), strm);
    string key = "processes";
    string line;
    int num_proc = 0;
    while(getline(strm, line)){

        if(line.compare(0,key.size(), key) == 0){
            stringstream ss(line);
            ss >> key >> num_proc; //overwriting "key" variable
            break;
        }
    }

    return num_proc;
}


int ProcessParser::getNumberOfRunningProcesses(){
    ifstream strm;
    Util::getStream(Path::basePath()+Path::statPath(), strm);
    string key = "procs_running";
    string line;
    int run_proc = 0;
    while(getline(strm, line)){

        if(line.compare(0,key.size(), key) == 0){
            stringstream ss(line);
            ss >> key >> run_proc; //overwriting "key" variable
            break;
        }
    }

    return run_proc;
}


string ProcessParser::getOSName(){
    string line;
    string key = "PRETTY_NAME=";

    ifstream stream;
    Util::getStream("/etc/os-release", stream);

    while (getline(stream, line)) {
        if (line.compare(0, key.size(), key) == 0) {
              std::size_t found = line.find("=");
              found++;
              string result = line.substr(found);
              result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
              return result;
        }
    }
    return "";

}


std::string ProcessParser::PrintCpuStats(std::vector<std::string> values1, std::vector<std::string>values2){
    float activeTime = ProcessParser::get_sys_active_cpu_time(values2) - ProcessParser::get_sys_active_cpu_time(values1);
    float idleTime = ProcessParser::get_sys_idle_cpu_time(values2) - ProcessParser::get_sys_idle_cpu_time(values1);
    float totalTime = activeTime + idleTime;
    float result = 100.0*(activeTime / totalTime);
    return to_string(result);
}


bool ProcessParser::isPidExisting(string pid){
    vector<string> pid_list = ProcessParser::getPidList();
    for(string _pid : pid_list){
        if(pid == _pid)
            return true;
    }
    return false;
}
