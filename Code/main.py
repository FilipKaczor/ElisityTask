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

    def search_for_brute_force(self):
        print("Searching for brute force logs...")




test_object = main("../Files/sample_security.log")
test_object.processing_dividing()
print(test_object.logs_class)
print( "\033[33m" + f"{test_object.logs_divided}")
