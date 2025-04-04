from pycrate_asn1dir import NGAP
from pycrate_mobile.NAS5G import *
from binascii import unhexlify
from typing import Iterator
from time import time
import pyshark, tomllib, os

# ====================================================================================== #
#                                                                                        #
#                                       CONSTANTS                                        #
#                                                                                        #
# ====================================================================================== #

CONFIG_FILE = "fuzzer/src/config.toml"

# Filter type
WHITELIST = 0
BLACKLIST = 1

# Default behavior
FUZZ_THEN_SEND_PACKET = 0
SEND_PACKET = 1
BLOCK_PACKET = 2
RAISE_ERROR = 3

# ====================================================================================== #
#                                                                                        #
#                                       FUNCTIONS                                        #
#                                                                                        #
# ====================================================================================== #

class Timekeeper:
    def __init__(self):
        self.start_time = time()

    def start(self):
        self.start_time = time()

    def getTime(self):
        return time()-self.start_time
    
    def printTime(self):
        print(f'{round(time()-self.start_time,3)} s')

class NAS_Filter():


    def __init__(self, configuration):
        self.filterType:int = None
        self.filterOnFailBehavior:int = None
        self.rules:dict[str] = None

        filter_configuration = configuration["Filter"]
        match filter_configuration["filterType"]:
            case "whitelist":
                self.filterType = WHITELIST
            case "blacklist":
                self.filterType = BLACKLIST
            case _:
                raise ValueError(f"Error: filter type {filter_configuration["filterType"]} not accepted.")
        
        match filter_configuration["filterOnFailBehavior"]:
            case "fuzzThenSendPacket":
                self.filterOnFailBehavior = FUZZ_THEN_SEND_PACKET
            case "sendPacket":
                self.filterOnFailBehavior = SEND_PACKET
            case "blockPacket":
                self.filterOnFailBehavior = BLOCK_PACKET
            case "raiseError":
                self.filterOnFailBehavior = RAISE_ERROR
            case _:
                raise ValueError(f"Error: filter on fail behavior parameter {filter_configuration["filterOnFailBehavior"]} not accepted.")

        self.rules = filter_configuration["apply"]



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
def returnPathsFromEndpoint(paths: Iterator[any], endpoint:any) -> list[any]:
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





# ====================================================================================== #
#                                                                                        #
#                                       MAIN                                             #
#                                                                                        #
# ====================================================================================== #


def main():
    ngap_pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    configuration = getConfiguration()
    filter = NAS_Filter(configuration)
    files = initGetAllInputFiles(configuration)

    # We are using pyshark. Pyshark is simple to use but has very high overhead. We might want to change library in the future when we try to optimize.
    capture_file = pyshark.FileCapture('data/amf_3_1.cap', display_filter="ngap", include_raw=True, use_ek=True, keep_packets=False)

    for packet in capture_file:
        # The ngap_raw object doesn't seem to have a 'value' attribute. Raw data is seemingly stored in _fields_dict
        # We have also the problem that the packets are paresed twice: once by pyshark and another time by pycrate.
        unhexlified_string = unhexlify(packet.ngap_raw._fields_dict)
        ngap_pdu.from_aper(unhexlified_string)

        raw_original_message:bytes = getNASmessage(ngap_pdu)
        if raw_original_message is not None:
            original_message, err = parse_NAS5G(raw_original_message)
            assert not err
            print(original_message.show())
        else:
            print("No NAS message.")


main()