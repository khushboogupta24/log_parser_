# logparser
 Parses log files against lookup file to obtain data

Project Overview

This project/problem is a command-line tool designed to parse flow log data, map each row to a tag based on a lookup table, and generate an output file that includes counts of tags and port/protocol combinations. 
The program is written in Python, using only built-in libraries, without the need for additional dependencies.

Assumptions

Flow Log Format:    
    The program supports only the default flow log format (version 2).  
    The flow log must contain at least 8 fields for each entry. If an entry has fewer than 8 fields, it will be skipped (error handling).
    The lookup table and log files are plain text (ASCII).
    The lookup table file should have a header row, which will be ignored during processing.

Protocol Support:
    All Protocols supported provided in IANA
    The program is case-insensitive when matching protocol and port values with the lookup table.
    Custom protocol versions or non-standard entries are not supported.


Lookup Table:
The lookup table should be a CSV file with three columns: dstport, protocol, and tag.
where:  
    dstport = destination port number.
    protocol = protocol name (e.g., tcp, udp).

Tag is the tag assigned to the dstport,protocol combination.
The script assumes the protocol field in the lookup table matches the protocol names in the protocol_mapping dictionary and is unique.

Error Handling: 

    File Not Found: Add error handling to manage cases where the input files do not exist or cannot be opened.
    Invalid Data: Handle cases where the input files have invalid or malformed data.
    Missing Protocols: Provide a fallback or warning if a protocol number is not mapped in protocol_mapping.    

Untagged Entries:
If a flow log entry does not match any entry in the lookup table, it is counted as "Untagged."

Installation and Setup

Prerequisites
    Python 3.x installed on your machine.

Running the Program
Prepare Input Files:
    Create/obtain a flow log file in the correct format (.txt file).
        flow log file name should be "logs.txt"
    Create/obtain a lookup table in CSV format.
        lookup table file name should be "lookup.csv"

Run the Program:
Save the provided Python script (log_parser.py) in a directory.
Run the program using the following command:
    python3 log_parser.py 


Testing and Validation
Tests Performed
Basic Functionality:
    Tested with sample flow logs and lookup tables to ensure correct tagging and counting.

Validation
    Compare Outputs: Manually verify that the output matches expected results based on your sample data.

Edge Cases:
    Empty logs.txt
    No matching entries in lookup.csv.
    Logs with protocols not included in protocol_mapping.


Known Limitations

Custom Log Formats: The program does not support custom log formats. Only the default format as described is supported.

Analysis and Further Considerations

Simple: Only Python's built-in libraries
Efficient: Run on any machine with Python installed without additional setup.
Extensibie/Polymorphic: Support additional protocols, custom log formats
