from typing import Iterator
from lib.constants import *
import tomllib, os.path

# Logging
import logging
logger = logging.getLogger(__name__)



def xorHexStrings(string_iter: Iterator[str]) -> str:
    xored_output:int = 0
    for string in string_iter:
        try:
            xored_output ^= int(string, 16)
        except ValueError as e :
            print(e)
            return None
    return hex(xored_output)


# Returns absolute paths so that we can then use "set_val_at()" function to change the value we wanted.
# In case multiple paths match, all of them will be returned.
# This is NOT EFFICIENT (O(n*m)), but this is the only way to have a general function that can find this.
def returnPathsFromEndpoint(paths: Iterator, endpoint) -> list:
    valid_paths:list[list] = []
    for path in paths:
        if endpoint in path[0]: # Actual path, path[1] is endpoint value. We could think about getting path[1] too if we wanted the value.
            valid_paths.append(path[0])
    
    return valid_paths

def getNASmessage(pdu):
    output = None
    paths = returnPathsFromEndpoint(pdu.get_val_paths(),"NAS-PDU")
    if len(paths)!=0:
        output = pdu.get_val_at(paths[0])
    return output




def getConfiguration():
    output:dict = None
    try:
        with open(CONFIG_FILE, "rb") as config_file:
            output=tomllib.load(config_file)
    except Exception as e:
        raise e
    return output





# Watch out: no protection against loops from logic links !
def getAllInputFiles(path_list:list[str], flag_recursive_search:bool)->set[str]:
    output:set[str] = set()
    try:
        for path in path_list:
            if os.path.isfile(path):
                output.add(path)
            elif os.path.isdir(path) and flag_recursive_search:
                output.update(getAllInputFiles([path+"/"+path_addendum for path_addendum in os.listdir(path)], flag_recursive_search))
            else:
                raise FileNotFoundError(f"Error: file or directory {path} does not exist.")
    except Exception as e:
        raise e
    return output

def initGetAllInputFiles(configuration)->set[str]:
    output:set[str] = set()
    flag_recursive_search = (configuration["Input"]["inputTraversal"]=="recursive")
    if configuration["Input"]["inputType"]=="pcap":
        output = getAllInputFiles(configuration["Input"]["inputFiles"], flag_recursive_search)
    return output



