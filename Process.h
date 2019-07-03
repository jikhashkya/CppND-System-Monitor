#include <string>

using namespace std;
/*
Basic class for Process representation
It contains relevant attributes as shown below
*/
class Process {
private:
    string pid;
    string user;
    string cmd;
    string cpu;
    string mem;
    string upTime;

public:
    Process(string pid){
        this->pid = pid;
        this->user = ProcessParser::getProcUser(pid);
        //TODOs:
        this->mem = ProcessParser::getVmSize(pid);
        //complete for cmd
        this->cmd = ProcessParser::getCmd(pid);
        //complete for upTime
        this->upTime = ProcessParser::getProcUpTime(pid);
        //complete for cpu
        this->cpu = ProcessParser::getCpuPercent(pid);
        
    }
    void setPid(int pid);
    string getPid()const;
    string getUser()const;
    string getCmd()const;
    int getCpu()const;
    int getMem()const;
    string getUpTime()const;
    string getProcess();
};
void Process::setPid(int pid){
    this->pid = pid;
}
string Process::getPid()const {
    return this->pid;
}
string Process::getProcess(){
    if(!ProcessParser::isPidExisting(this->pid))
        return "";
    this->mem = ProcessParser::getVmSize(this->pid);
    this->upTime = ProcessParser::getProcUpTime(this->pid);
    this->cpu = ProcessParser::getCpuPercent(this->pid);

    return (this->pid + "   " +
            this->user + "   " +
            this->mem.substr(0,5) + "   " +
            this->cpu.substr(0,5) + "   " +
            this->upTime.substr(0,5) + "   " +
            this->cmd.substr(0,5) );
    //TODO: finish the string! this->user + "   "+ mem...cpu...upTime...;
}
