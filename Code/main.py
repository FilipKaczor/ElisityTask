from datetime import datetime
class main:
    def __init__(self, file_name:str):
        """
        file_name - string with logs file name
        all_logs - list of all logs
        logs_class - list of logs classes by severity
        logs_divided - list of lists of logs divided by severity
        colors - list of colors used for console output
        """

        self.file_name = file_name
        self.all_logs = []
        self.logs_class = []
        self.logs_divided = []
        self.colors = (
            "\033[32m",  # Green - Info
            "\033[91m",  # Red - Error
            "\033[33m",  # Yellow - Warning
            "\033[95m",  # Light Magenta - Custom
        )

    def processing_dividing(self):

        """
        :return: None

        idea: logs are preprocessed, unified and divided into different classes by severity
        """

        with open(self.file_name, "r") as f:
            for line in f:

                new_line = []
                word_count = 0

                '''delete brackets from date and hour'''
                for word in line.split():
                    if (word_count == 0):
                        new_line.append(word[1:])
                    elif (word_count == 1):
                        new_line.append(word[:-1])
                    else:
                        new_line.append(word)
                    word_count += 1

                '''address issue where sql injection was separated by " "'''
                if len(new_line) > 6:
                    merged = " ".join(new_line[5:])
                    new_line = new_line[:5] + [merged]

                '''add processed logs into main list'''
                self.all_logs.append(new_line)

                '''divide logs into classes by the severity'''
                if new_line[2] not in self.logs_class:
                    self.logs_class.append(new_line[2])
                    self.logs_divided.append([])
                    new_log_class_index = self.logs_class.index(new_line[2])
                    self.logs_divided[new_log_class_index].append(new_line)
                else:
                    new_log_class_index = self.logs_class.index(new_line[2])
                    self.logs_divided[new_log_class_index].append(new_line)

    def search_for_brute_force(self, logs:list[str], amount_threshold:int, time_threshold:int):

        """
        :param logs:list[str] - list of logs to search through for brute force
        :param amount_threshold:int - lower limit for amount of logs in brute force to display
        :param time_threshold:int - maximum timespan between logs to be recognized as one attack
        :return: None

        idea: logs are searched through, using 'FAILED_LOGIN', for brute force attacks and separated by unique ip addresses and time between attacks
        """

        brute_force_logs = []
        brute_force_ip_addresses = []

        '''
        current_index - index of the log list with specific ip address
        time_index - index of the log list with specific time difference
        time_difference - difference of time from current log and last log in last time list
        
        if time_difference is below time_threshold log is inserted into time_list with last log, if not new list is created for this specific ip address

        idea is to check if logs in brute force attack were right after each other in short time interval 
        
        presentation of processed data:
        [ division by ip address [ division by time [logs]]]
        '''

        for log in logs:
            if log[4] == "FAILED_LOGIN":
                if log[3] in brute_force_ip_addresses:

                    current_index = brute_force_ip_addresses.index(log[3])
                    time_index = len(brute_force_logs[current_index])-1
                    last_log_index = len(brute_force_ip_addresses[current_index][time_index])-1

                    time_difference = datetime.strptime(f"{log[0]} {log[1]}", "%Y-%m-%d %H:%M:%S") - datetime.strptime(f"{brute_force_logs[current_index][time_index][last_log_index][0]} {brute_force_logs[current_index][time_index][last_log_index][1]}", "%Y-%m-%d %H:%M:%S")
                    time_difference = time_difference.total_seconds()

                    if time_difference < time_threshold:
                        brute_force_logs[current_index][time_index].append(log)
                    else:
                        time_index+=1
                        brute_force_logs[current_index].append([])
                        brute_force_logs[current_index][time_index].append(log)
                else:
                    brute_force_ip_addresses.append(log[3])
                    brute_force_logs.append([[log]])

        '''
        check if brute force attempts were past amount_threshold per ip address
        results are displayed in console using custom colors to emphasise crucial information such as ip addresses and timespan
        '''

        print(self.colors[0],"Searching for brute force logs... \n")
        for logs_per_ip in brute_force_logs:
            for logs_per_time in logs_per_ip:
                if len(logs_per_time) >= amount_threshold:
                    print(self.colors[2], f"From ip address {self.colors[1]} {brute_force_ip_addresses[brute_force_logs.index(logs_per_ip)]}")
                    print(self.colors[2], f"In time span: {logs_per_time[0][0]} {logs_per_time[0][1]} - {logs_per_time[len(logs_per_time)-1][0]} {logs_per_time[len(logs_per_time)-1][1]}")
                    print(self.colors[1], f"Were {len(logs_per_time)} attempts of brute force")
                    print(self.colors[1], f"On account names: \n  " + "\n  ".join(log[5].split("=")[1] for log in logs_per_time))
                    print("\n")

    def search_for_sql_injection(self, logs:list[str]):

        """
        :param logs:list[str] - list of logs to search through for sql injection attempts
        :return: None

        idea: logs are searched through using 'SQL_INJECTION_ATTEMPT' in event type and separated by unique ip addresses
        """

        print(self.colors[0],"Searching for sql injection logs... \n")
        sql_injection_logs = []
        sql_injection_ip_addresses = []

        for log in logs:
            if log[4] == "SQL_INJECTION_ATTEMPT":
                if log[3] not in sql_injection_ip_addresses:
                    sql_injection_ip_addresses.append(log[3])
                    sql_injection_logs.append([log])
                else:
                    sql_injection_logs[sql_injection_ip_addresses.index(log[3])].append(log)

        '''
        results are displayed in console using custom colors to emphasise crucial information such as ip addresses and used SQL queries
        '''

        for ip_address in sql_injection_ip_addresses:
            print(self.colors[2], f"From ip address {self.colors[1]} {ip_address}")
            print(self.colors[2], f"were {len(sql_injection_logs[sql_injection_ip_addresses.index(ip_address)])} attempt(s) of sql injection")
            for logs_per_ip in sql_injection_logs[sql_injection_ip_addresses.index(ip_address)]:
                print(self.colors[1], f"using: {logs_per_ip[5].split("=")[1]}")
            print("\n")


    def search_for_unusual_access_logs(self, logs:list[str]):

        """
        :param logs:list[str] - list of logs to search through for unusual access attempts
        :return: None
        idea: logs are searched through using 'UNUSUAL_ACCESS' in event type and separated by unique ip addresses
        """

        print(self.colors[0],"Searching for unusual access logs... \n")

        unusual_access_logs = []
        unusual_access_logs_ip_addresses = []

        for log in logs:
            if log[4] == "UNUSUAL_ACCESS":
                if log[3] not in unusual_access_logs_ip_addresses:
                    unusual_access_logs_ip_addresses.append(log[3])
                    unusual_access_logs.append([log])
                else:
                    unusual_access_logs[unusual_access_logs_ip_addresses.index(log[3])].append(log)

        '''
        results are displayed in console using custom colors to emphasise crucial information such as ip addresses and targeted directory
        '''

        for ip_address in unusual_access_logs_ip_addresses:
            print(self.colors[2], f"From ip address {self.colors[1]} {ip_address}")
            print(self.colors[2],
                  f"were {len(unusual_access_logs[unusual_access_logs_ip_addresses.index(ip_address)])} attempt(s) of unusual access")
            for logs_per_ip in unusual_access_logs[unusual_access_logs_ip_addresses.index(ip_address)]:
                print(self.colors[1], f"to directory: {logs_per_ip[5]}")
            print("\n")

    def search_for_port_scan(self, logs:list[str]):
        print(self.colors[0],"Searching for port scan logs... \n")
        #todo


'''testing examples of methods'''
test_object = main("../Files/sample_security.log")
test_object.processing_dividing()
# test_object.search_for_brute_force(test_object.logs_divided[test_object.logs_class.index("WARNING")], 2, 10)
# test_object.search_for_sql_injection(test_object.logs_divided[test_object.logs_class.index("ERROR")])
test_object.search_for_unusual_access_logs(test_object.logs_divided[test_object.logs_class.index("ERROR")])
