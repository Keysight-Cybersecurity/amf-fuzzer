### amf-fuzzer

A simple fuzzing tool for testing AMF through mutated NGAP/NAS packets. 


## Organization:
- Objectives
- To do list


## Objectives

The goal of this project is to create a fuzzer for uplink NGAP/NAS-5Gs packets targeting the AMF network function. These fuzzed packets will then, when associated with the corresponding AMF answer, create a dataset for an AI to train on.

This training AI will have for objective to protect the function from perceived threats. As such, the fuzzing has to be done in such a way that it manages to create packets making AMF behave in unexpected ways, and reliably. In order to do some smart fuzzing, the program will also need to understand the answers of AMF. Another AI may be needed for that (see AFL).


## To do list

# Functionalities (MAJOR)
[X] Filter (NAS+NGAP)
[ ] Dissect for modification
[ ] Fuzz
[ ] Manage response
[ ] Adapt fuzzing from response
[ ] Save results

# Functionalities (Macro)
[X] Create a configuration file.
[X] Manage to extract data in a smart way from pcap files.
[ ] Manage to extract data from live packets.
[X] Implement a filter for PDUs.
[ ] Implement a way to reliably select packet fields to fuzz.
[ ] Implement at least one fuzzing engine.
[ ] Implement a dumb fuzzing engine.
[ ] Find a way to implement reliable error recognition from AMF (AI or another parser ?)
[ ] Implement packet-to-response association for smart fuzzing.
[ ] Implement a smart mutation fuzzing engine.
[ ] Implement AFL as a fuzzing engine.
[ ] Find the best way.s to implement output file generation for AI training then implement it.
[ ] (Optional) Check if NyxNet is free of rights then implement it.
[ ] (Optional) Check if SnapFuzz is free of rights then implement it.
[ ] (Optional) Check if ProFuzzBench is free of rights then implement it.

# Functionalities (micro)
[X] Find a way to linearize tree structure of parsed NAS-5Gs protocol for filtering.
[ ] Modify filter rule validation from endpoint-value to key-value comparison so that only endpoints are considered and not whole path. (Configuration becomes way harder as there can be multiple endpoints with the same name)

# Cleanliness
[ ] (Security) Implement a grammar with local verification of variables for boolean expression on filters (filter_engines.py).
[X] (Security) Implement a tokenization obfuscation technique to avoid arbitrary variable reassignment from evaluation of key-value filter rules (filter_engines.py).
[ ] (Readability) Properly implement a logger in all files.
[ ] (Readability) Properly write the docstring in all files.
[ ] (Readability) Add more comments and restructure functions for better readability.