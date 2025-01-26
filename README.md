
# Flow Log Parser 

## Overview
FlowLogParser is a Java application designed to process and analyze network flow logs using concurrent processing. It parses flow log files, categorizes traffic based on ports and protocols, and generates statistical reports.

## Assumptions

### Protocol Handling
1. Default Protocol Support:
    - Limited to 8 predefined protocols in default PROTOCOL_MAP:
    - Any protocol, port combination not in the map is labeled as "Untagged"
    - Custom protocol mappings can be provided via optional protocol_map_file

### Flow Log Format
1. Flow Log Version:
    - Assumes VPC Flow Logs version 2 format
    - No header row in flow log file
    - Each line must contain minimum 8 fields:
      ```
      src dst bytes srcport dstport ip dstport protocol
      ```
    - Lines with fewer than 8 fields are skipped
    - Fields are space-separated

2. Field Requirements:
    - protocol (field 8): Must be a numeric protocol identifier
    - Invalid or malformed fields result in line being skipped
    - No validation of other fields as they're not used in analysis

### Processing Behavior

#### Counting Logic:
    - Each valid line increments both tag and port-protocol counters
    - Duplicate lines are counted separately
    - "Untagged" is used when no matching tag is found in lookup table

## Compile
```
javac src/FlowLogParser.java -d .

javac -cp .:lib/junit-platform-console-standalone-1.8.2.jar src/FlowLogParserTest.java -d .
```

## Run Program
```
java FlowLogParser ./data/flowlogfile.txt ./data/lookuptable.csv ./output.txt

java -jar lib/junit-platform-console-standalone-1.8.2.jar --class-path . --select-class FlowLogParserTest
```
## Testing Details

### Unit Tests Implemented

1. Basic Functionality Tests
   - Validates lookup table loading
   - Tests single line processing
   - Validates concurrent processing

2. Edge Cases
   -  Tests duplicate entries
   -  Test malformed input
   -  Test empty files

3. Error Handling Tests
   - Invalid protocol numbers
   - Missing fields
   - Malformed input lines

### Performance Testing
- Tested with 100,000+ flow log records approximately 10MB
- Measured processing time for large datasets
- Confirmed proper thread utilization



