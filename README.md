# log_analyzer
a command line tool to analyze the content of log files via given operations as input and return an output after having performed operations on the given input.

Command line tool for squid logs analyze

Parameters:

    Input data:
        `-input` : path to one or more plain text files or directory
                accepted file extensions: .log, .text
    Operations:
        `-mfip` : the most frequent IP
        `-lfip` : the least frequent IP
        `-eps` : events per second
        `-t` : total amount of bytes exchanged
    Output:
        `-output`: path to a file to save output in plain text JSON format by default or to a specified format
        if the output is not provided, it considers the current working directory
    **USAGE** : in terminal (Command line)
    >python main.py -h : for help
    >python main.py -input [path_to_file(s)] [operations]
    >python main.py -input [path_to_file(s)] [operations] -output [path_to_save_file]
    e.g:
       [x]python main.py -input access.log -mfip  -> for most frequent ip in access.log
       [x]python main.py -input access.log -mfip -lfiq -eps -t -> for most frequent ip, least frequent ip, events per second and total amount of bytes exchanged in access.log
       [x]python main.py -input access.log -t -output /Users/SwissRe/Desktop -> for total amount of bytes exchanged in access.log, results saved in /Users/SwissRe/Desktop      

