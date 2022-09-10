# @Gilda

import os, sys
import json

# This list contains the command line keywords corresponding to the operations.
# Please add new keywords as you add new operations in the class Operations

params=['-h','-input', '-mfip', '-lfip', '-eps', '-t', '-output']


class Verifier:
    """ This class implements the analyzer, it contains verification methods and other methods of the analyzer.
    """
    def __init__(self, inputs, output):
        """constructor of the analyzer class
        Args:
            inputs (str): path, directory or file
            output (str): destination path or folder
        """
        self.inputs=inputs
        self.output=output  
    
    def OR(self, elt, types:list) -> bool:
        for typ in types:
            if elt.endswith(typ): return True
        return False
    
    def get_files(self, dir, types):
        """ method that gets all the plain text files in the directory
        Args:
            dir (str): the input file or folder
            types (list, optional): list of file types to consider. Defaults to [".log", ".text"].
        Returns:
            list: the list of files to be considered as log files
        """
        file=[]
        try:
            contents = os.listdir(dir)
            for element in contents:  
                if self.OR(element, types):
                    file.append((os.path.abspath(element), os.path.basename(element)))
        except:
            file.append((os.path.abspath(dir), os.path.basename(dir)))       
        return file
               
    def input_output_verification(self, types=[".log"]):
        """ checking if output path is not provided, replace it by the current working directory
        Args:
            types (list, optional): list of input file formats to consider. Defaults to [".log"].
        Returns:
            tuple: the verified input and output paths or folders
        """
        if not os.path.exists(str(self.inputs)) or not os.path.exists(str(self.output)):
             print("Invalid Input path")
             sys.exit()
        return (self.get_files(self.inputs, types), self.output)
    
    def operations_verification(self, *ops):
        """ method that checks if the provided operations are correct or not
        Returns:
            list: list of verified operations
        """
        if type(ops)==tuple: ops=ops[0]
        return ops if set(ops) <= set(params) else "Invalid Operations"           
    
class Operations(Verifier):
    """ class that contains operations to perform on our logs. It inherits from Analyzer class 
        These might be extended to newer operations.
        those are:
            mostFreqIp: method that determines the most frequent ip address
            leastFreqIp: method that determines the least frequent ip address
            eventsPerSec: method that determines the number of events per second
            totalAmOfBytesEx: method that implements the total amount of Bytes exchanged
            
        Important: to add a new operation, just add it as a new method of this class
    Args:
        Analyzer (class): the parent class containing verification methods
    """
    def __init__(self, inputs, output, *ops):
        """ Constructor of the operations class. This class inherits from Analyzer methods
        Args:
            inputs (str): path, directory or file
            output (str): destination path or folder 
        """
        super().__init__(inputs, output, *ops)
        self.inputs, self.output = inputs, output # getting the input path after check
        try:
            with open(self.inputs, 'r') as logs:
                self.lines=logs.readlines()
                logs.close()
            with open(self.inputs, 'r') as logs:
                self.all_file=logs.read()
                logs.close()
        except:
            print("Can\'t open file") 
        try:
            if not len(self.lines[0].split())==10: 
                self.ips=[line.split()[2] for line in self.lines[1:]]
            else:
                self.ips=[line.split()[2] for line in self.lines[0:]]
            self.ips_freq={ip:self.all_file.count(ip) for ip in set(self.ips)}
        except:
            print("Not valid format in log file")
    
    @property
    def mostFreqIp(self): #-> str:
        """ Property that returns the most frequent client Ip address in the input log file
        Returns:
            list: client ip(s) with the frequency of appearance corresponding to the most frequent in the log file
        """
        self.dict_sorted_desc=dict(sorted(self.ips_freq.items(), key=lambda x: x[1], reverse=True))
        self.ordered_dico_descending= list(self.dict_sorted_desc.items())
        #rep=[self.ordered_dico_descending[i][0] for i in range(len(self.ordered_dico_descending)) if self.ordered_dico_descending[i][1]==self.ordered_dico_descending[0][1]]+[self.ips_freq[self.ordered_dico_descending[0][0]]]
        return [self.ordered_dico_descending[i][0] for i in range(len(self.ordered_dico_descending)) if self.ordered_dico_descending[i][1]==self.ordered_dico_descending[0][1]]+[self.ips_freq[self.ordered_dico_descending[0][0]]] #rep[0] if len(rep)==1 else rep
    
    @property
    def leastFreqIp(self): #-> str:
        """ Property that returns the least frequent client Ip address in the input log file
        Returns:
            list: client ip(s) with the frequency of appearance corresponding  to the least frequent in the log file
        """
        self.dict_sorted_asc=dict(sorted(self.ips_freq.items(), key=lambda x: x[1]))
        self.ordered_dico_ascending=list(self.dict_sorted_asc.items())
        return [self.ordered_dico_ascending[i][0] for i in range(len(self.ordered_dico_ascending)) if self.ordered_dico_ascending[i][1]==self.ordered_dico_ascending[0][1]]+[self.ips_freq[self.ordered_dico_ascending[0][0]]]#rep[0] if len(rep)==1 else rep
    
    @property
    def eventsPerSec(self): #-> str:
        """method that returns the mean number of events per second.
           I assume here events to be the records 
        Returns:
            float: the number of events per second
        """
        if not len(self.lines[0].split())==10: 
            timestamp_data=[float(line.split()[0]) for line in self.lines[1:]]
            timestamp_data.sort()
        else:
            timestamp_data=[float(line.split()[0]) for line in self.lines[0:]]
            timestamp_data.sort()
        return len(timestamp_data)/(timestamp_data[len(timestamp_data)-1]-timestamp_data[0]) # here I make the difference between the last timestamp and first one (sorted) to get the elapsed timestamp
    
    @property
    def totalAmOfBytesEx(self):
        """method that returns the total amount of Bytes exchanged
        Returns:
            int: the total amount of bytes exchanges, ie Response header size + Response size
        """
        try: #if not len(self.lines[0].split())==10: 
            self.all_headers_sizes=[int(line.split()[1]) for line in self.lines[1:]]
            self.all_response_sizes=[int(line.split()[4]) for line in self.lines[1:]]
        except: #else:
            self.all_headers_sizes=[int(line.split()[1]) for line in self.lines]
            self.all_response_sizes=[int(line.split()[4]) for line in self.lines]
        return sum(self.all_headers_sizes)+sum(self.all_response_sizes)
    
    def save(self, *param, format="json"):
        """ method that saves results of operations (output) in a file format provided
        Args:
            *param (list): list of operations 
            format (str, optional): the format in which the output can be saved. Defaults to "json".
        """
        if not self.operations_verification(*param) == "Invalid Operations":
            content={}
            for ops in self.operations_verification(*param):
                # operations can be added here, make sure the corresponding operations properties or methods have been added in the class first
                if ops=='-mfip': content["most_freq_ip"]=self.mostFreqIp
                if ops=='-lfip': content["least_freq_ip"]=self.leastFreqIp
                if ops=='-eps': content["events_per_second"]=self.eventsPerSec
                if ops=='-t': content["total_amount_bytes_exchanged"]=self.totalAmOfBytesEx
            if format=="json":
                file_name=str(self.inputs[:self.inputs.index(".")])+"__analysis_results.json"
                file_name=self.output+"/"+os.path.basename(file_name)
                print(f" name of file: {file_name}")
                save_file=open(file_name, "a")
                save_file.write(json.dumps(content)+"\n")
            elif format in ["txt", "text"]:
                file_name=str(self.inputs[:self.inputs.index(".")])+"__analysis_results.txt"
                file_name=self.output+"/"+os.path.basename(file_name)
                save_file=open(file_name, "a")
                for key, value in content.items():
                    save_file.write(f"{key}:{value}\n")
            else:
                print("This format is not defined yet, please add it first!")
            save_file.close()
            output_path = os.path.abspath(file_name)
            print(f"results saved in {output_path}")
        else:
            print("Invalid Operations")
            
    
        
    

    
