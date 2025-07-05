file_path = "../Files/sample_security.log"
all_logs = []
logs_class = []
logs_divided = []
with open(file_path, "r") as f:
    for line in f:

        new_line = []
        word_count = 0

        '''deleted brackets from date and hour'''
        for word in line.split():
            if(word_count==0):
                new_line.append(word[1:])
            elif(word_count==1):
                new_line.append(word[:-1])
            else:
                new_line.append(word)
            word_count+=1

        '''adressed issue where sql injection was separated by " "'''
        if len(new_line)>6:
            merged = " ".join(new_line[5:])
            new_line = new_line[:5] + [merged]

        '''adding processed logs into main list'''
        all_logs.append(new_line)

        '''dividing logs into classes by the severity'''
        if new_line[2] not in logs_class:
            logs_class.append(new_line[2])
            logs_divided.append([])
            new_log_class_index = logs_class.index(new_line[2])
            logs_divided[new_log_class_index].append(new_line)
        else:
            new_log_class_index = logs_class.index(new_line[2])
            logs_divided[new_log_class_index].append(new_line)

print(logs_class)
print(all_logs)
print(logs_divided[2])