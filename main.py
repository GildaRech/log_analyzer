# @Gilda
import sys
import json 
import os

from code import Operations, Verifier, params


help_="""
Command line tool for squid logs analyze \n
Parameters:
    Input data:
        -input : path to one or more plain text files or directory
                accepted file extensions: .log, .text
    Operations:
        -mfip : the most frequent IP
        -lfip : the least frequent IP
        -eps : events per second
        -t : total amount of bytes exchanged
    Output:
        -output: path to a file to save output in plain text JSON format by default or to a specified format
        if the output is not provided, it considers the current working directory
    USAGE: in terminal (Command line)
    python main.py -h : for help
    python main.py -input [path_to_file(s)] [operations]
    python main.py -input [path_to_file(s)] [operations] -output [path_to_save_file]
    e.g:
       python main.py -input access.log -mfip      -> for most frequent ip in access.log
       python main.py -input access.log -mfip -lfiq -eps -t     -> for most frequent ip, least frequent ip, events per second and total amount of bytes exchanged in access.log
       python main.py -input access.log -t -output /Users/SwissRe/Desktop  -> for total amount of bytes exchanged in access.log, results saved in /Users/SwissRe/Desktop      
"""

if __name__=="__main__":
    
    if set([ operation for operation in sys.argv[1:] if operation.startswith("-")]) <= set(params):
        ind_output_path=-1
        if "-output" in sys.argv:
            ind_output_path=sys.argv.index("-output")
            try:
                sys.argv[ind_output_path+1]
            except:
                ind_output_path=-1
            
        if len(sys.argv)==1:
            print("squid logs analyzer v 1.0, @Swiss Re")
            print(" Invalid argument. Please type python main -h for help.")
            sys.exit()
            
        elif len(sys.argv)==2 and sys.argv[1]=="-h":
            print(help_)
            sys.exit()
            
        elif "-input" not in sys.argv :
            print("Missing input file path")
            sys.exit()

        elif len(sys.argv)==3 and sys.argv[1]=="-input":
            print("Missing operation(s)")
            sys.exit()
            
        elif len(sys.argv)==4 and "-output" in sys.argv[1:]:
            print("Missing operation(s)")
            sys.exit()
            
        elif len(sys.argv)>=4 and sys.argv[1]=="-input" and sys.argv[3] in ['-mfip',  '-lfip', '-eps', '-t']:
            if not ind_output_path==-1:
                inputs, output = Verifier(sys.argv[2], sys.argv[ind_output_path+1]).input_output_verification(types=[".log"]) # different input log files can be considered with types
                for file_info in inputs: 
                    args=sys.argv[3:]
                    args.pop()
                    Operations(file_info[0], output).save(args, format="json") # saving in different file formats like text, json,..
            else:
                inputs, output = Verifier(sys.argv[2], os.getcwd()).input_output_verification(types=[".log"]) # different input log files can be considered with types
                for file_info in inputs: 
                    Operations(file_info[0], output).save(sys.argv[3:], format="json")
        elif len(sys.argv)==2 and sys.argv[1] in set(params)-set(["-h", "-input"]):
            print("parameter missing")
            sys.exit()

    else:
        print("Incorrect operation")
        sys.exit()