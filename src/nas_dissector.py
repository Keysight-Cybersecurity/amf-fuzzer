
# ====================================================================================== #
#                                                                                        #
#                                       IMPORTS                                          #
#                                                                                        #
# ====================================================================================== #

# Imports from standard library.
from binascii import unhexlify
from datetime import *

# Imports from downloaded libraries
from pycrate_asn1dir import NGAP # pycrate
from pycrate_mobile.NAS5G import * # pycrate
import pycrate_core.elt
import pyshark #pyshark

# Imports from local library
from lib.filter_engines import *
from lib.fuzzing_engine import *
from lib.functions import *

# Logging
import logging
logger = logging.getLogger(__name__)


# ====================================================================================== #
#                                                                                        #
#                                     FUNCTIONS                                          #
#                                                                                        #
# ====================================================================================== #

def flatten_nas5g_tree_recursive_envelope_traversal(envelope:pycrate_core.elt.Envelope)->list[str]:
    paths:list = []
    for next_item in envelope._content:
        next_item:pycrate_core.elt.Element
        if next_item.CLASS == 'Atom':
            paths.append((next_item.fullname().replace(".",", "), next_item._val))
        elif next_item.CLASS == 'Envelope':
            paths+=flatten_nas5g_tree_recursive_envelope_traversal(next_item)
    return paths


def unhexlified_packet_to_endpoint_paths(data_container, protocol_type, packet):
    match protocol_type:
        # The ngap_raw object doesn't seem to have a 'value' attribute. Raw data is seemingly stored in _fields_dict
        # We have also the problem that the packets are paresed twice: once by pyshark and another time by pycrate.
        case "ngap":
            try:
                unhexlified_string = unhexlify(packet.ngap_raw._fields_dict)
                data_container.from_aper(unhexlified_string)
                return data_container.get_val_paths()
            except Exception as e:
                logger.error(f"Error: with protocol ngap, filter_input expects a PDU, got a {type(data_container)}")

        case "nas-5gs": # Do note, this is for NAS message that are still containerized by NGAP
            try:
                unhexlified_string = unhexlify(packet.ngap_raw._fields_dict)
                data_container.from_aper(unhexlified_string)
                raw_original_message:bytes = getNASmessage(data_container)
                if raw_original_message is not None:
                    original_message, err = parse_NAS5G(raw_original_message)
                    assert not err
                    return flatten_nas5g_tree_recursive_envelope_traversal(original_message)
                else:
                    print("No NAS message.")
                    logger.warning("No NAS message in NGAP packet while in NAS branch, check functionality of pyshark brancher.")
            except Exception as e:
                pass
        case _:
            logger.error("No function to retrieve paths of endpoints from filter_input.")
    return None

# ====================================================================================== #
#                                                                                        #
#                                       MAIN                                             #
#                                                                                        #
# ====================================================================================== #



def main():
    
    # Get configuration for further... configuration. Filename is in lib.constants.
    configuration = getConfiguration()

    # Start logger
    logging.basicConfig(filename=configuration["Logging"]["directory"]+"/"+"fuzzer_log_"+datetime.now().strftime("%Y%d%m%H%M%S")+".log", level=logging.INFO)
    logger.info(f"Starting at {datetime.now()}")

    # Establish a profile depending on protocol to parse.
    protocol_filter:PDU_Filter = PDU_Filter(configuration)
    data_container = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    str_protocol_name = configuration["Middleware"]["protocol"]
    if str_protocol_name not in ["ngap","nas-5gs"]:
        logger.error(f"Protocol {configuration["Middleware"]["protocol"]} is not taken in charge or is invalid.")
        str_protocol_name = None
        exit(1) #TODO: Manage

    # Establish a profile depending on protocol to parse.
    fuzzer_engine:FuzzerEngine
    match configuration["Middleware"]["fuzzerEngine"]:
        case "dumb":
            logger.info(f"{configuration["Middleware"]["fuzzerEngine"]} Still not implemented.")
            pass
        case "mutation":
            logger.info(f"{configuration["Middleware"]["fuzzerEngine"]} Still not implemented.")
            pass
        case "afl":
            logger.info(f"{configuration["Middleware"]["fuzzerEngine"]} Still not implemented.")
            pass
    

    # Parse and apply modifications in case the input type is pcap files.
    match configuration["Input"]["inputType"]:
        case "pcap":

            file_paths = initGetAllInputFiles(configuration)
            for file_path in file_paths:
            # We are using pyshark. Pyshark is simple to use but has very high overhead. We might want to change library in the future when we try to optimize.
                capture_file = pyshark.FileCapture(file_path, display_filter=str_protocol_name, include_raw=True, use_ek=True, keep_packets=False)
                for packet in capture_file:
                    endpoint_paths = unhexlified_packet_to_endpoint_paths(data_container, str_protocol_name, packet)
                    behaviour_indicator = protocol_filter.get_behaviour(endpoint_paths) # Goes nowhere for now

        case "live":
            logger.info(f" {configuration["Input"]["inputType"]} is still not implemented.")
        
        case _:
            logger.warning("inputType entry value does not match valid entries.")
    

    logger.info(f"Stopped succesfully at {datetime.now()}")



if __name__ == '__main__':
    main()
