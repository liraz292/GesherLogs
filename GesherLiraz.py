# Imports
import socket
import sys
import re
import datetime
import time
import os
import csv
import random
import threading
import signal

# Globals
REGEX_NEW_CONNECTION   = r"\<(?P<version>\d.\d)\>\s\[(?P<serverName>\w+)\]\s\((?:\w+)\)\s(?P<date>\d+/\d+/\d+\s\d+:\d+:\d+)\s\[(?P<logType>\w+)\]\s\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s\[(?:.*)\]:\s(?P<message>.*ID\s(?P<connectionID>\d+).*\(gpconf ID: (?P<gpconfID>\d+).*@\s(?P<sourceAddress>\d+\.\d+\.\d+\.\d+):(?P<sourcePort>\d+) to (?P<destinationAddress>\d+\.\d+\.\d+\.\d+):(?P<destinationPort>\d+))"
# <1.0> [Galash_Logic] (GENERAL) 12/07/20 09:21:00 [NOTICE] {RED CPU | NETWORKING} [24.4]: Created new connection conn with ID 24216 (gpconf ID: 2) @ 160.1.111.1:38416 to 150.1.111.1:20001

REGEX_ADD_FW_RULE      = r"\<(?P<version>\d.\d)\>\s\[(?P<serverName>\w+)\]\s\((?:\w+)\)\s(?P<date>\d+/\d+/\d+\s\d+:\d+:\d+)\s\[(?P<logType>\w+)\s+\]\s\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s\[(?:.*)\]:\s(?P<message>Added new FW.*ID\s(?P<ruleID>\d+).*)"
# <1.0> [Galash_Logic] (GENERAL) 12/07/20 11:07:31 [INFO  ] {SIVIM_XML_FILTER | CONNECTION MANAGER} [28.51]: Added new FW rule with ID 46614

REGEX_CLOSING_CONNECTION = r"\<(?P<version>\d.\d)\>\s\[(?P<serverName>\w+)\]\s\((?:\w+)\)\s(?P<date>\d+/\d+/\d+\s\d+:\d+:\d+)\s\[(?P<logType>\w+)\s+\]\s\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s\[(?:.*)\]:\s(?P<message>(?:Closing connection (?P<connectionID>\d+)).*)"
# <1.0> [Galash_Logic] (GENERAL) 12/07/20 14:06:26 [DEBUG ] {RED CPU | CONTROL} [24.26]: Closing connection 26594 after request from purple

REGEX_FORMAT_1         = r"\<(?P<version>\d(?:.\d)?)\>\s\[(?P<serverName>\w+)\]\s(?P<date>\w+\s\w+\s\d+\s\d+:\d+:\d+\s\d+)\s<(?:\w+)>\s\[(?P<logType>\w+)\]\s+\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s(?:(?P<sourceAddress>\d+\.\d+\.\d+\.\d+):(?P<sourcePort>\d+)-?\[?(?P<userName>\w+)?\]?)?\s?(?P<message>.*)"
# all the logs with time format: Sun Jul 12 14:07:28 2020

REGEX_HTTP_MESSAGE     = r"\<(?P<version>\d.\d)\>\s\[(?P<serverName>\w+)\]\s\((?:(?P<gpconfID>\d)\s(?P<connectionID>\d+)\s(?P<sourceAddress>\d+\.\d+\.\d+\.\d+):(?P<sourcePort>\d+) -> (?P<destinationAddress>\d+\.\d+\.\d+\.\d+):(?P<destinationPort>\d+))\)\s(?P<date>\d+/\d+/\d+\s\d+:\d+:\d+)\s\[(?P<logType>\w+)\s+\]\s\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s\[(?:.*)\]:\s(?P<message>.*)"
# <1.0> [Galash_Logic] (2 26613 150.1.111.3:20001 -> 160.1.111.3:43523) 12/07/20 11:07:31 [DEBUG ] {SIVIM_XML_FILTER | HTTP MESSAGE VALIDATOR} [29.24]: Started handling an HTTP response

REGEX_ALERT_CPU        = r"\<(?P<version>\d(?:.\d)?)\>\s\[(?P<serverName>\w+)\]\s\w+\W\s\[\s(?P<logType>\w+)\s\]\s\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s\s(?P<message>.*)"
# <1.0> [Galash_Physical] Agent: [ ALERT ] {RED CPU | SNMP AGENT}  Red CPU didn't respond in the specified timeout

REGEX_XML_LOG          = r"\<(?P<version>\d(?:.\d)?)\>\s\[(?P<serverName>\w+)\]\s(?P<date>\w+\s\w+\s\d+\s\d+:\d+:\d+\s\d+)\s<(?:\w+)>\s\[(?P<logType>\w+)\]\s+\{(?P<logSource>.*)\s\|\s(?P<logSubSource>.*)\}\s(?:(?P<sourceAddress>\d+\.\d+\.\d+\.\d+):(?P<sourcePort>\d+)-?\[?(?P<userName>\w+)?\]?)?\s?(?P<message>.*\.xm.*)"
# <1.0> [Galash_Logic] Tue Apr 20 09:58:37 2021 <r0> [INFO]  {RED CPU | FTP} Successfully sent 1036993641.xml to other CPU
# <1.0> [Galash_Logic] Tue Apr 20 09:58:37 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50045-[usera] <- STOR 1036993641.xml

REGEX_FTP              = r"\<(?P<version>\d(?:.\d)?)\>\s\[(?P<serverName>\w+)\]\s(?P<date>\w+\s\w+\s\d+\s\d+:\d+:\d+\s\d+)\s<(?:\w+)>\s\[(?P<logType>\w+)\]\s+\{(?P<logSource>.*)\s\|\s(?P<logSubSource>FTP)\}\s(?:(?P<sourceAddress>\d+\.\d+\.\d+\.\d+):(?P<sourcePort>\d+)-?\[?(?P<userName>\w+)?\]?)?\s?(?P<message>.*)"
# <1.0> [Galash_Logic] Tue Apr 20 14:05:30 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:63688-[usera] -> 230 Login successful.

REGEX_XML_MESSAGE     = r".* \'?(.+)\.xm.*"

COULMN_NAMES        = ["version", "serverName", "date", "logType", "logSource", "logSubSource", "message", "userName", "sourceAddress", "sourcePort", \
                       "destinationAddress", "destinationPort", "connectionID", "gpconfID", "ruleID", "type"]

REGEXES             = {"NEW_CONNECTION" : REGEX_NEW_CONNECTION, "ADD_FW_RULE" : REGEX_ADD_FW_RULE, "CLOSING_CONNECTION" : REGEX_CLOSING_CONNECTION, \
                       "HTTP_MESSAGE" : REGEX_HTTP_MESSAGE, "ALERT_CPU" : REGEX_ALERT_CPU, "XML_FILE" : REGEX_XML_LOG, "FTP" : REGEX_FTP, "FORMAT_1" : REGEX_FORMAT_1}

REGEXES_KEYS_LIST        = ["NEW_CONNECTION", "ADD_FW_RULE", "CLOSING_CONNECTION", "HTTP_MESSAGE", "ALERT_CPU", "XML_FILE", "FTP", "FORMAT_1"]

FTP_MESSAGES_REGEXS = [r'-> \d* Login successful.',r"USER 'usera' logged in.", r'<- CWD RECEIVE', r'-> \d* "/root/FTP_retr_red" is the current directory.', r'<- CWD fromcmr', r'<- PORT \*',\
                       r'-> \d* Active data connection established.', r'<- NLST', r'-> \d* Data connection already open. Transfer starting.', r'-> \d* Transfer complete.', r'<- QUIT', r'-> \d* Goodbye.',\
                       r'FTP session closed \(disconnect\)\.', r'FTP session opened \(connect\)', r'connected', r'-> \d* Gesher Plada FTP Server.', r'<- USER usera', r'-> \d* Username ok, send password.',\
                       r'<- PASS \*\*\*\*\*\*', r'<- RETR .*\.xml', r'<- DELE .*.xml', r'-> * Failed deleting .*\.xml from server, Internal communication error, Status: \d*.', r'<- CWD SEND', r'<- CWD tocmr', \
                       r'<- STOR .*\.xml', r'STOR  completed=.* bytes=.* seconds=.*\..*', r'RETR .*\.xm completed=.* bytes=.* seconds=.*\..*', r'Successfully sent .*\.xm to client',\
                       r'Converted retries value: .* -> Retry\(total=.*, connect=.*, read=.*, redirect=.*\)', r'Problem occurred, code: \d*, message: \d* No such file or directory.', r'Starting new HTTP connection \(\d*\): ([0-9]{1,3}\.){3}[0-9]{1,3}',\
                       r'\"POST /STOR HTTP/*.*\" \d* \d*', r'Successfully sent \*\*\.xml to other CPU', r'\"POST /DELE HTTP/.*\..*\" 500 None',\
                       r'Internal communication error, Status: \d*', r'Received file: .*\.xml', r'Trying to delete file: \*\*\.xml', r'Received file \'\*\*\.xml\' from client. Sending to remote server', \
                       r'Failed removing file, Exception Occurred: Internal communication error, Status: \d*', r'-> \d* Failed deleting \*\*\.xml from server, Internal communication error, Status: \d*\.']

TIME_FORMAT         = "%a %b %d %H:%M:%S %Y"
TIME_FORMAT_2       = "%d/%m/%y %H:%M:%S"
TIME_FORMAT_3       = "%Y-%m-%d %H:%M:%S"
TIME_FORMAT_4       = "%Y-%m-%d %H:%M:%S.%f"
LIST_TIME_FORMATS   = [TIME_FORMAT, TIME_FORMAT_2, TIME_FORMAT_3, TIME_FORMAT_4]
BUFFER_SIZE         = 4096
DESTINATION_ADDRESS = ("150.1.69.126", 1999)
SESSIONS_FOLDER     = r"C:\users\yaring\desktop\GP\sessions"
LOG_FOLDER          = r"C:\users\yaring\desktop\GP\logs"
OVERRIDE_SIZE       = 10485760L
SESSION_INTERVAL    = 40
TRANSFER_INTERVAL   = 10
SESSIONS_THRESHOLD  = 150
LEN_XML_FILE_1      = 10
LEN_XML_FILE_2      = 11
exit_event = threading.Event()


class Gesher():
    
    def __init__(self, name, ip, port):
        self.sessions = []
        self.logs = [] # Logs that are not yet linked to any session
        self.name = name
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("", self.port))   

    def add_session(self, session):
        self.sessions.append(session)

    def remove_session(self, session):
        self.sessions.remove(session)

    def drop_duplicated_sessions(self):
        self.sessions = set(self.sessions)

    def add_log(self, log_dict):
        self.logs.append(log_dict)

    def remove_log(self, log_Dict):
        self.logs.remove(log_dict)
            

class Session():
    
    def __init__(self, firstLogDict, first_raw_log):
        self.logs = []
        self.add_log(firstLogDict)
        self.first_raw_log = first_raw_log
        self.start_time = firstLogDict['date']
        self.sourceAddress = firstLogDict['sourceAddress']
        self.sourcePort = firstLogDict['sourcePort']
        self.logSource = firstLogDict['logSource']
        self.logSubSource = firstLogDict['logSubSource']
        self.gpconfID = firstLogDict['gpconfID']
        self.connectionID = firstLogDict['connectionID']
        self.serverName = firstLogDict['serverName']
        self.ruleID = firstLogDict['ruleID']
        self.type = firstLogDict['type']

 
    def add_log(self, log_dict):
        """
        Add log to the session
        """

        # fixing some too specific messages
        if 'PORT' in log_dict['message']:
            log_dict['message'] = '<- PORT *'
            
        elif re.search(r'\d+\.xml',log_dict['message']):
            log_dict['message'] = re.sub(r'\d+\.xml', '**.xml', log_dict['message'])
            
        elif re.search(r'\d+\.xm',log_dict['message']):
            log_dict['message'] = re.sub(r'\d+\.xm', '**.xm', log_dict['message'])
            
        elif re.search(r'ID \d+', log_dict['message']):
            log_dict['message'] = re.sub(r'ID \d+.*', 'ID ***', log_dict['message'])
            
        elif re.search(r'Closing connection \d+', log_dict['message']):
            log_dict['message'] = re.sub(r'Closing connection \d+', 'Closing connection ****', log_dict['message'])
            
        elif re.search(r'\d+\_ack.xm',log_dict['message']):
             log_dict['message'] = re.sub(r'\d+\_ack.xm', '**_ack.xm', log_dict['message'])
        
        self.logs.append(log_dict)


    def get_elapsed_time(self):
        """
        Get the number of seconds from the last log related to the session to the current time
        """
    
        return(convert_string_to_datetime(str(datetime.datetime.now())) - convert_string_to_datetime(self.start_time)).total_seconds()


    def __repr__(self):
        return("serverName: {}, " \
               "logs length: {}, "\
               "start_time: {}, "\
               "sourceAddress: {}, "\
               "sourcePort: {}, "\
               "logSource: {}, "\
               "logSubSource: {}, "\
               "gpconfID: {}, "\
               "connectionID: {}, "\
               "ruleID: {}"\
               .format(self.serverName, len(self.logs), self.start_time,
                       self.sourceAddress, self.sourcePort, self.logSource,
                       self.logSubSource, self.gpconfID, self.connectionID,
                       self.ruleID))


    def __eq__(self, s2):
        if len(self.logs) != len(s2.logs):
            return False
        
        for log1, log2 in zip(self.logs, s2.logs):
            if log1['message'] != log2['message']:
                return False

        return True 


    def __sub__(self, s2):
        
        count_different = 0
        
        for log1, log2 in zip(self.logs, s2.logs):
            if log1['message'] != log2['message']:
                count_different += 1

        return count_different


def signal_handler():
    exit_event.set()

    
def raw_log_to_dict(log):
    """
    Format raw log to dictionary
    """
    
    log_dict = dict.fromkeys(COULMN_NAMES,"")
    
    for regex in REGEXES_KEYS_LIST:
        if re.search(REGEXES[regex], log):
            log_dict.update(re.search(REGEXES[regex], log).groupdict())
            log_dict["type"] = regex
            break

            # removing None values from log dict
            for key in log_dict.keys():
                if log_dict[key] is None:
                    log_dict[key] = ""
            
            log_dict["date"] = convert_string_to_datetime(log_dict["date"])

            return log_dict

    # log didn't match any regex
    return log_dict


def convert_string_to_datetime(date_str):
    """
    Convert the string to datetime in format "%Y-%m-%d %H:%M:%S"
    """
    
    for time_format in LIST_TIME_FORMATS:

        try:
            time = datetime.datetime.strptime(date_str, time_format)
        except ValueError:
            continue

    return time


# name  message version serverName date  logType logSource userName sourceIP sourcePort dstIP  dstPort connectionID gpconfID ruleID fullLog
def send_log_to_siem(s_out, name, message, log_dict, full_log):
    """
    Send suspicious log to GP syslog connector, listening in port 1999
    """

    # Fix the None values which makes Error in Arcsight parser
    for key in log_dict.keys():
        if log_dict[key] == None:
            log_dict[key] = ""

    s_out.sendto("${}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}\n".format(name, message, log_dict["version"], log_dict["serverName"], log_dict["date"],
                log_dict["logType"], log_dict["logSource"], log_dict["userName"], log_dict["sourceAddress"], log_dict["sourcePort"],
                log_dict["destinationAddress"], log_dict["destinationPort"], log_dict["connectionID"],
                log_dict["gpconfID"], log_dict["ruleID"], full_log), DESTINATION_ADDRESS)
    print('log sent', message)


# name message "" serverName start_time "" logSource "" sourceAddress sourcePort "" "" connectionID gpconfID ruleID full_session
def send_sessions_to_siem(s_out, name, message, gesher):
    """
    Send suspicious sessions to GP syslog connector, listening in port 1999
    """

    for session in gesher.sessions:
        s_out.sendto("${}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}~{}\n".format(name, message, "", session.serverName, session.start_time,
                    "", session.logSource, "", session.sourceAddress, session.sourcePort,"", "", session.connectionID, session.gpconfID,
                    session.ruleID, session), DESTINATION_ADDRESS)
    print('{} sessions has sent'.format(len(gesher.sessions)))


def is_known_session(gesher, session):
    """
    Check if the session has been seen in one of the csv files already written to disk
    """
    
    root_folder = os.path.join(SESSIONS_FOLDER, gesher.ip+"\\FTP\\")
    for root, dirs, files in os.walk(root_folder):
        for file_name in files:
            session_logs = []
            file_path = os.path.join(root_folder, file_name)

            with open(file_path, 'rb') as csvFile:
                reader = csv.DictReader(csvFile)
                for row in reader:
                    session_logs.append(row)

            if len(session_logs) != len(session.logs):
                continue

            found_similar_session = True
            for log1, log2 in zip(session_logs, session.logs):
                if log1['message'] != log2['message']:
                    found_similar_session = False
                    break

            if found_similar_session:
                return True
            
    return False  


def dump_session_to_csv(gesher, session):
    """
    Dump session to csv file
    """
    
    path = os.path.join(SESSIONS_FOLDER, gesher.ip, "FTP")
    if not os.path.exists(path):
        os.mkdir(path)
    path_session_file = os.path.join(path,"{}_{}.csv".format(session.sourceAddress, session.sourcePort))
    if not os.path.exists(path_session_file):
        with open(path_session_file, 'wb') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=COULMN_NAMES)
            writer.writeheader()
            for log_dict in session.logs:
                writer.writerow(log_dict)
    else:
        with open(path_session_file, 'ab') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=COULMN_NAMES)
            for log_dict in session.logs:
                writer.writerow(log_dict)



def write_log_to_disk(gesher, log_dict):
    
    path = os.path.join(LOG_FOLDER, gesher.ip + ".csv")
    # write to local disk
    if os.path.exists(path) and os.path.getsize(path) < OVERRIDE_SIZE:
        with open(path, 'ab') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=COULMN_NAMES)
            writer.writerow(log_dict)
            
    else:
        with open(path, 'wb') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=COULMN_NAMES)
            writer.writeheader()
            writer.writerow(log_dict)


def recieve_logs(gesher):
    """
    Recieve logs from geshers
    """

    numLogsRecieved = 0
    i = 0
    while True:
        if exit_event.is_set():
            break
        
        log, addr = gesher.socket.recvfrom(BUFFER_SIZE) # Recieve log
        #print(log)
        #print(type(log))
        #with open(r"C:\Users\Lirazk\Desktop\logs.txt", 'a') as file_descriptor:
        #    file_descriptor.write(log)
        #log_dict = raw_log_to_dict(log) # Format log to dictionary
        #log_list = ["<1.0> [Galash_Logic] Wed Nov 10 15:19:04 2021 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:55555-[usera] -> 200 Active data connection established."]
        #log_list = ["<1.0> [Galash_Logic] Sun Jan 02 17:00:00 2022 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:44683-[usera] -> 200 Active data connection established.",\
        #            "<1.0> [Galash_Logic] Sun Jan 02 17:00:00 2022 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:49245-[usera] -> 200 Activ data connection established.",\
        #            "<1.0> [Galash_Logic] Sun Jan 02 17:00:00 2022 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:49381-[usera] -> 200 Active data connection established."]
        #log_list = ["<1.0> [Galash_Logic] (GENERAL) 02/01/22 11:46:02 [NOTICE] {RED CPU | NETWORKING} [24.4]: Created new connection conn with ID 51471 (gpconf ID: 1) @ 160.1.111.1:20000 to 150.1.111.1:55021",\
        #            "<1.0> [Galash_Logic] (1 51471 150.1.111.1:55021 -> 160.1.111.1:20000) 02/01/22 11:46:02 [DEBUG ] {RED CPU | HTTP HEADERS PARSER} [29.23]: Started handling an HTTP request",\
        #            "<1.0> [Galash_Logic] (GENERAL) 02/01/22 11:46:02 [DEBUG ] {RED CPU | CONTROL} [24.26]: Closing connection 51471 after request from purple"]
        """log_list = ['<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:50872-[] FTP session opened (connect)',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:50872 connected',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[] -> 220 Gesher Plada FTP Server.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[] <- USER usera',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[] -> 331 Username ok, send password.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- PASS ******',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 230 Login successful.',\
"<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:50872-[usera] USER 'usera' logged in.",\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- CWD RECEIVE',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 250 "/root/FTP_retr_red" is the current directory.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- CWD fromcmr',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 250 "/root/FTP_retr_red" is the current directory.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- PORT 150,1,102,4,198,186',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 200 Active data connection established.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- NLST',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 125 Data connection already open. Transfer starting.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 226 Transfer complete.',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] <- QUIT',\
'<1.0> [Galash_Logic] Mon Nov 08 12:56:31 2021 <r0> [DEBUG]  {RED CPU | FTP} 150.1.102.4:50872-[usera] -> 221 Goodbye.',\
'<1.0> [Galash_Logic] Tue Apr 20 09:57:06 2021 <r0> [DEBUG]  {RED CPU | FTP} "POST /DELE HTTP/1.1" 500 None',\
    '<1.0> [Galash_Logic] Tue Apr 20 09:58:38 2021 <r0> [ERROR]  {RED CPU | FTP} Internal communication error, Status: 500',\
        "tjgnjtnjygnj"]"""
        #log_list =["<1.0> [Galash_Logic] Sun Jan 02 17:00:00 2022 <r0> [INFO]  {RED CPU | FTP} 150.1.102.4:49245-[usera] -> 200 Activ data connection established."]
        #log_list =[""]
        #if i < 1:
        log_dict = raw_log_to_dict(log)
        gesher.add_log((log_dict, log))
            #print("*********************")
            #print(gesher.logs)
            #print("********************")
            #print("***************")
            #print(log_dict)
            #print("***************")
            #i+=1
        numLogsRecieved += 1


def logs_with_different_codes(gesher, s_out, log_dict, log):
    """
    Check for differnet code numbers in the differnet logs
    """
    
    logs_regex = [('-> (.*) Gesher Plada FTP Server.', '220'), ('-> (.*) Username ok, send password.', '331'), ('-> (.*) Login successful.', '230'), ('-> (.*) "/root/FTP_retr_red" is the current directory."', '250'), \
                  ('-> (.*) Active data connection established.', '200'), ('-> (.*) Data connection already open. Transfer starting.', '125'), ('-> (.*) Transfer complete.', '226'), \
                  ('-> (.*) Goodbye.', '221'), ('"POST /STOR HTTP/(.*)" (.*) (.*)', ('1.1', '204', '0')), ('"POST /DELE HTTP/(.*)" (.*) (.*)', ('1.1', '500', 'None')), \
                  ('Starting new HTTP connection \((.*)\): .*', '1'), ('Problem occurred, code: (.*), message: (.*) No such file or directory.', ('500', '550')), \
                  ('Internal communication error, Status: (.*)', '500'), ('Failed removing file, Exception Occurred: Internal communication error, Status: (.*)', '500'), \
                  ('-> (.*) Failed deleting \d+\.xml from server, Internal communication error, Status: (.*)\.', ('550', '500'))]
    
    for log_regex in logs_regex:
        code = re.match(log_regex[0], log_dict["message"])
        if code:

            if ((type(log_regex[1]) == tuple and code.groups() != log_regex[1]) or \
                ((type(log_regex[1]) != tuple and code.group(1) != log_regex[1]))):
                send_log_to_siem(s_out, "Different code number in FTP message", "Code numbers are {} in gesher {}. Should be {}. the message is: {}".format(code.group(1), gesher.name, log_regex[1], log_dict["message"]), log_dict, log)


def ftp_check_logs(gesher, log_dict, log, s_out, found_similar_session):
    """
    Check FTP log's anomaly
    """
    
    # Check if the source address is not 150.1.102.4
    if log_dict["sourceAddress"] != None and log_dict["sourceAddress"] != "150.1.102.4":
        send_log_to_siem(s_out, "Unknown source address", "Source address {} is different from 150.1.102.4 in gesher {}".format(log_dict["sourceAddress"],gesher.name), log_dict, log)

    # not the default user name
    if log_dict["userName"] not in ["usera", None]:
        send_log_to_siem(s_out, "Unknown user name", "User name is {} in gesher {}. Should be usera or Null.".format(log_dict["userName"], gesher.name), log_dict, log)

    # Check if the log type is uncommon
    if log_dict["logType"] not in ["INFO","DEBUG", "NOTICE", "ERROR",""]:
        send_log_to_siem(s_out, "Uncommon log type", "Log type is {} in gesher {}. Should be INFO, DEBUG, NOTICE, ERROR or Null.".format(log_dict["logType"], gesher.name), log_dict, log)      

    # Check if the source port length is not 5
    if log_dict["sourcePort"] != None and len(log_dict["sourcePort"]) != 5:
        send_log_to_siem(s_out, "Different source port length","Source port length is {} in gesher {}. Should be 5.".format(len(log_dict["sourcePort"]),gesher.name), log_dict,log)

    # Check if message is different from normal FTP regexes messages
    for regex in FTP_MESSAGES_REGEXS:
        if re.match(regex, log_dict["message"]):
            break
    else:
        send_log_to_siem(s_out, "Uncommon FTP message", "FTP message: {} in gesher {} is different from the normal FTP messages.".format(log_dict["message"], gesher.name), log_dict, log)
        print(log_dict["message"])
    
    # Check for differnet code numbers in the differnet logs
    logs_with_different_codes(gesher, s_out, log_dict, log)
"""
    # Check if source ports decrease between sessions
    if len(gesher.sessions) > 1:
        for session in gesher.sessions:
            if session.sourcePort == log_dict["sourcePort"] and session.sourcePort and session.sourceAddress == log_dict["sourceAddress"] not in [None, ""] \
                and session.sourceAddress and session.type == log_dict["type"]: 
                session_index = gesher.sessions.index(session)
                if found_similar_session:
                    break
                #print("session index: {}".format(session_index))
                #print(gesher.sessions)
                while session_index > 0:
                    if gesher.sessions[session_index - 1].sourcePort and gesher.sessions[session_index - 1].sourceAddress:
                        if gesher.sessions[session_index - 1].sourcePort > log_dict["sourcePort"] and gesher.sessions[session_index - 1].type == log_dict["type"] == "FTP":
                            print("Source ports decrease")
                            send_log_to_siem(s_out, "Source ports decrease between sessions", "Source port of the first session is {} and source port of the session after is {} in gesher {}. Source ports should increase between sessions."\
                            .format(gesher.sessions[session_index - 1].sourcePort, log_dict["sourcePort"], gesher.name), log_dict, log)
                            break
                    session_index-=1
"""


def check_logs(gesher, s_out):
    """
    Check log's anomaly and attach them to the relevant session
    """

    numLogsAnalyzed = 0

    while True:

        if exit_event.is_set():
            break
        
        if gesher.logs != []:
            log_dict, log = gesher.logs.pop(0) # Retrieve first log in list
            #print("\n!!!!!!!!!!Retrieved!!!!!!!! {}".format(log))
            found_similar_session = False
          
            # check if the log did not match any of our regexes                
            if log_dict == dict.fromkeys(COULMN_NAMES, ""):
                send_log_to_siem(s_out, "Unknown log format", "The log did not match any regex in gesher {}".format(gesher.name), log_dict, log)
                continue
                 
            # Check if the server name is uncommon
            if log_dict["serverName"] not in ["Galash_Logic", "Galash_Physical"]:
                send_log_to_siem(s_out, "Uncommon server name", "Server name is {} in gesher {}. Should be Galash_Logic or Galash_Physical.".format(log_dict["serverName"], gesher.name), log_dict, log)

            # Check if the version is not 1.0
            if log_dict["version"] != "1.0":
                send_log_to_siem(s_out, "Unknown version", "Version is {} in gesher {}. Should be 1.0".format(log_dict["version"], gesher.name), log_dict, log)

            # Check if xml file name isn't 10 digits long or not contain only digits
            if log_dict["type"] == "XML_FILE":
                xml_name = re.match(REGEX_XML_MESSAGE, log_dict["message"]).group(1)
                if xml_name != '' and (not xml_name.isdigit() or (len(xml_name) != LEN_XML_FILE_1 and len(xml_name) != LEN_XML_FILE_2)):
                    send_log_to_siem(s_out, "Uncommon XML file name", "XML file name: {} in gesher {} should be 10 digits long and contain only digits.".format(xml_name, gesher.name), log_dict, log )

            # Check if a session that the log belongs to exists
            for session in gesher.sessions:
                # In case the log is with the same source address, source port, log source and sub log source
                if (session.sourceAddress != '' and session.sourcePort != '') and \
                    (session.sourceAddress == log_dict["sourceAddress"] and session.sourcePort == log_dict["sourcePort"] and \
                    session.logSource == log_dict["logSource"] == 'RED CPU' and session.logSubSource == log_dict["logSubSource"] == 'FTP'):
                    
                    session.add_log(log_dict)
                    #session.start_time = datetime.datetime.now()
                    found_similar_session = True
                    break                                  
              
                # In case the log is with the same connection id or rule id
                elif (session.connectionID != '' and session.connectionID == log_dict["connectionID"]) or \
                    (session.ruleID != '' and session.ruleID == log_dict["connectionID"]):
                    
                    session.add_log(log_dict)
                    #session.start_time = datetime.datetime.now()
                    found_similar_session = True
                    break

            # If it's a new session
            if not found_similar_session:
                gesher.add_session(Session(log_dict, log))

            # Check anomaly for FTP logs
            if log_dict["logSubSource"] == "FTP" and log_dict["type"] == "FTP":
                ftp_check_logs(gesher, log_dict, log, s_out, found_similar_session)

            #print(gesher.sessions)
            write_log_to_disk(gesher, log_dict)
            numLogsAnalyzed += 1


def close_sessions(gesher):
    """
    Close sessions by closing log or timeout
    """

    while True:

        if exit_event.is_set():
            break
        
        for session in gesher.sessions:

            messages = [log["message"] for log in session.logs]
            
            # If it's a closing log or the log has reached the timeout
            if "FTP session closed" in messages or "Closing connection" in messages or session.get_elapsed_time() >= SESSION_INTERVAL:
                if session.sourceAddress not in ["", None] and session.sourcePort not in ["", None]:
                    dump_session_to_csv(gesher, session)
                    #print("\n[+] Found new session with connection ID: {}".format(session.connectionID))
                    #print("\n[+] The session has dump to csv with conn {}:{}".format(session.sourceAddress, session.sourcePort))
                gesher.remove_session(session) # Remove session from sessions list


def check_sessions_overflow(gesher, s_out):
    """
    Check for an overflow of sessions' incomes or drops
    """  

    while True:
        
        if exit_event.is_set():
            break
        
        numSessions = len(gesher.sessions)
        # Check if minute has passed
        time.sleep(60)
        # Check if number of sessions has passed the legitimate limit
        if len(gesher.sessions) - numSessions >= SESSIONS_THRESHOLD:
            send_sessions_to_siem(s_out, "Sessions Overflow", "An overflow of {} sessions in a minute in gesher {} has been detected".format(len(gesher.sessions),gesher.name), gesher)
        

    
def main():

    gesher_logical = Gesher("logi", "150.1.111.1", 3001)
    gesher_physical = Gesher("physi", "150.1.111.2", 3002)
    gesher_physical_backup = Gesher("logi backup", "150.1.111.3", 3003)
    gsharim = [gesher_logical]
    s_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    threads_list = []
    signal.signal(signal.SIGINT, signal_handler)
 
    for gesher in gsharim:
        
        # Initialize Services
        recieve_logs_service = threading.Thread(target=recieve_logs, args=(gesher, )) # Recieve logs
        check_logs_service = threading.Thread(target=check_logs, args=(gesher, s_out, )) # Check suspicious logs
        close_sessions_service = threading.Thread(target=close_sessions, args=(gesher, )) # Close sessions by closing log or timeout
        check_sessions_overflow_service = threading.Thread(target=check_sessions_overflow, args=(gesher, s_out, )) # Check for overflow in sessions incomes or drops

        services = [recieve_logs_service, check_logs_service, close_sessions_service, check_sessions_overflow_service]
        
        for service in services:
            threads_list.append(service)
            service.daemon = True
            service.start()

    try:
        for service in threads_list:

            service.join()

    except (KeyboardInterrupt, SystemExit):
        print("\n[-] Exiting...")
        for service in threads_list:
            service.join()
        for gesher in gsharim:
            gesher.socket.close()
            
        s_out.close()
        sys.exit(0)
        
    except Exception as e:
        print("\n[-] Error: {}".format(e))
        for service in threads_list:
            service.join()
        for gesher in gsharim:
            gesher.socket.close()

        s_out.close()
        sys.exit(0)
            
    
if __name__ == "__main__":    
    main()

