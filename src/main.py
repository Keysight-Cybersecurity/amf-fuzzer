
# ====================================================================================== #
#                                                                                        #
#                                       IMPORTS                                          #
#                                                                                        #
# ====================================================================================== #

# Imports from standard library.
from binascii import unhexlify
from datetime import *
from time import sleep

# Imports from downloaded libraries
from pycrate_asn1dir import NGAP # pycrate
from pycrate_mobile.NAS5G import * # pycrate
import pycrate_core.elt
import pyshark #pyshark

# Imports from local library
from lib.filter_engines import *
from lib.fuzzing_engine import *
from lib.functions import *
from lib.constants import *

# Logging
import logging
logger = logging.getLogger(__name__)


# ====================================================================================== #
#                                                                                        #
#                                     FUNCTIONS                                          #
#                                                                                        #
# ====================================================================================== #



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
    filter_protocol_name = configuration["Filter"]["protocol"]
    fuzzing_protocol_name = configuration["Middleware"]["protocol"]

    if fuzzing_protocol_name not in ["ngap","nas-5gs"]:
        logger.error(f"Protocol {fuzzing_protocol_name} is not taken in charge or is invalid.")
        fuzzing_protocol_name = None
        exit(1) #TODO: Manage
    if filter_protocol_name not in ["ngap", "nas-5gs"]:
        logger.error(f"Protocol {filter_protocol_name} is not taken in charge or is invalid.")
        fuzzing_protocol_name = None
        exit(1) #TODO: Manage

    # Establish a profile depending on fuzzer mode.
    fuzzer_engine:FuzzerEngine = DumbFuzzingEngine(configuration)
    #fuzzing_engine_manager = MultiEngineManager(configuration)

    # Parse and apply modifications in case the input type is pcap files.
    match configuration["Input"]["inputType"]:
        case "pcap":

            file_paths = getAllInputFiles(configuration["Input"]["inputFiles"], configuration["Input"]["inputTraversal"]=="recursive")
            for file_path in file_paths:
            # We are using pyshark. Pyshark is simple to use but has very high overhead. We might want to change library in the future when we try to optimize.
                capture_file = pyshark.FileCapture(file_path, display_filter=fuzzing_protocol_name, include_raw=True, use_ek=True, keep_packets=False)
                for packet in capture_file:
                    endpoint_paths = unifiedPathFinder(data_container, filter_protocol_name, packet)
                    behaviour_indicator = protocol_filter.get_behaviour(endpoint_paths)

                    if behaviour_indicator == FUZZ_THEN_SEND_PACKET:
                        if fuzzing_protocol_name == "ngap":
                            raw_data = packet.ngap_raw._fields_dict
                        elif fuzzing_protocol_name == "nas-5gs":
                            unhexlified_string = unhexlify(packet.ngap_raw._fields_dict)
                            data_container.from_aper(unhexlified_string)
                            raw_data = getNASmessage(data_container).hex()
                        # Ok there is something wrong here with the pdu. Where does it get updated ?
                        packet:Packet = Packet(pdu=data_container, data=raw_data, configuration=configuration)
                        fuzzer_engine.fuzzPacket(packet)
                        #fuzzing_engine_manager.fuzzingQueue.put(packet)
                    elif behaviour_indicator == SEND_PACKET:
                        #fuzzing_engine_manager.networkQueue.put(packet)
                        print(behaviour_indicator)
                    elif behaviour_indicator == BLOCK_PACKET:
                        continue
                    elif behaviour_indicator == RAISE_ERROR:
                        logger.error("Pattern matching requested for an exception to be raised.", exc_info=True)
                        raise Exception("Pattern matching requested error raised.")
                    else:
                        logger.error(f"Behaviour indicator n°{behaviour_indicator} does not exist", exc_info=True)
                        raise ValueError(f"Behaviour indicator n°{behaviour_indicator} does not exist.")

            # fuzzing_engine_manager.startAll()
            # sleep(5)
            # fuzzing_engine_manager.joinAll()

        case "live":
            logger.info(f" {configuration["Input"]["inputType"]} is still not implemented.")
        
        case _:
            logger.warning("inputType entry value does not match valid entries.")
    

    logger.info(f"Stopped succesfully at {datetime.now()}")



if __name__ == '__main__':
    main()
