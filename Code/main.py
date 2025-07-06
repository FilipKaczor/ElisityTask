from datetime import datetime
class main:
    def __init__(self, file_name):
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

    '''basic processing and dividing logs into classes by severity'''
    def processing_dividing(self):
        with open(self.file_name, "r") as f:
            for line in f:

                new_line = []
                word_count = 0

                '''deleted brackets from date and hour'''
                for word in line.split():
                    if (word_count == 0):
                        new_line.append(word[1:])
                    elif (word_count == 1):
                        new_line.append(word[:-1])
                    else:
                        new_line.append(word)
                    word_count += 1

                '''adressed issue where sql injection was separated by " "'''
                if len(new_line) > 6:
                    merged = " ".join(new_line[5:])
                    new_line = new_line[:5] + [merged]

                '''adding processed logs into main list'''
                self.all_logs.append(new_line)

                '''dividing logs into classes by the severity'''
                if new_line[2] not in self.logs_class:
                    self.logs_class.append(new_line[2])
                    self.logs_divided.append([])
                    new_log_class_index = self.logs_class.index(new_line[2])
                    self.logs_divided[new_log_class_index].append(new_line)
                else:
                    new_log_class_index = self.logs_class.index(new_line[2])
                    self.logs_divided[new_log_class_index].append(new_line)

    def search_for_brute_force(self, logs:list[str], amount_threshold:int, time_threshold:int):
        brute_force_logs = []
        brute_force_ip_addresses = []

        '''
        current_index - index of the log list with specific ip address
        time_index - index of the log list with specific time difference
        time_difference - difference of time from current log and last log in last time list
        if time_difference is below time_threshold log is inserted into time_list with last log, if not new list is created

        idea is to check if logs in brute force attack were right after each other in short time interval 
        '''

        for log in logs:
            if log[4] == "FAILED_LOGIN":
                if log[3] in brute_force_ip_addresses:

                    current_index = brute_force_ip_addresses.index(log[3])
                    time_index = len(brute_force_logs[current_index])-1
                    last_log_index = len(brute_force_ip_addresses[current_index][time_index])-1
                    time_difference = datetime.strptime(f"{log[0]} {log[1]}", "%Y-%m-%d %H:%M:%S") - datetime.strptime(f"{brute_force_logs[current_index][time_index][last_log_index][0]} {brute_force_logs[current_index][time_index][last_log_index][1]}", "%Y-%m-%d %H:%M:%S")
                    time_difference = time_difference.total_seconds()

                    if  time_difference < time_threshold:
                        brute_force_logs[current_index][time_index].append(log)
                    else:
                        time_index+=1
                        brute_force_logs[current_index].append([])
                        brute_force_logs[current_index][time_index].append(log)
                else:
                    brute_force_ip_addresses.append(log[3])
                    brute_force_logs.append([[log]])

        '''
        checking if brute force attempts were past amount_threshold per ip address
        '''

        print(self.colors[0],"Searching for brute force logs... \n")
        for logs_per_ip in brute_force_logs:
            for logs_per_time in logs_per_ip:
                if len(logs_per_time) >= amount_threshold:
                    print(self.colors[2], f"From ip address {brute_force_ip_addresses[brute_force_logs.index(logs_per_ip)]}")
                    print(self.colors[2], f"In time span: {logs_per_time[0][0]} {logs_per_time[0][1]} - {logs_per_time[len(logs_per_time)-1][0]} {logs_per_time[len(logs_per_time)-1][1]}")
                    print(self.colors[1], f"Were {len(logs_per_time)} attempts of brute force")
                    print(self.colors[1], f"On account names: \n  " + "\n  ".join(log[5] for log in logs_per_time))
                    print("\n")





test_object = main("../Files/sample_security.log")
test_object.processing_dividing()
# print(test_object.logs_class)
test_object.search_for_brute_force(test_object.logs_divided[1], 2, 10)