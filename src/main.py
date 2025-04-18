
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
from scapy.all import *

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
    NGAP_pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
    filter_protocol_name = configuration["Filter"]["protocol"]
    fuzzing_protocol_name = configuration["Middleware"]["protocol"]

    # Check if protocol is known. Will be obsolete once configuration testing function is created.
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

    # Parse and apply modifications in case the input type is pcap files.
    match configuration["Input"]["inputType"]:
        case "pcap":

            file_paths = getAllInputFiles(configuration["Input"]["inputFiles"], configuration["Input"]["inputTraversal"]=="recursive")
            for file_path in file_paths:
            # We are using pyshark. Pyshark is simple to use but has very high overhead. We might want to change library in the future when we try to optimize.
                capture_file = pyshark.FileCapture(file_path, display_filter=fuzzing_protocol_name, include_raw=True, use_ek=True, keep_packets=False)
                for wr_packet in capture_file:
                    endpoint_paths = unifiedPathFinder(NGAP_pdu, filter_protocol_name, wr_packet)
                    
                    # These behaviour indicators are integer values defined in lib.constants
                    behaviour_indicator = protocol_filter.get_behaviour(endpoint_paths)

                    if behaviour_indicator == FUZZ_THEN_SEND_PACKET:

                        if fuzzing_protocol_name == "ngap":
                            raw_data = wr_packet.ngap_raw._fields_dict
                            packet:Packet = Packet(pdu=NGAP_pdu, data=raw_data, configuration=configuration)
                            fuzzed_packet = fuzzer_engine.fuzzPacket(packet)
                            output_raw_data = fuzzed_packet.pdu.to_aper()

                        # We need to extract the NAS5G raw data from the NAS5G PDU, then create a NAS5G PDU,
                        # then modify it, then re-serialize the NAS5G PDU, apply the modifications to the NGAP PDU,
                        # then re-serialize the NGAP PDU.
                        elif fuzzing_protocol_name == "nas-5gs":
                            unhexlified_string = unhexlify(wr_packet.ngap_raw._fields_dict)
                            NGAP_pdu.from_aper(unhexlified_string)

                            # TODO
                            # This should be optimized. It doesn't make any sense to search for almost the same thing twice.
                            nas5G_element_from_ngap = getNASmessage(NGAP_pdu)
                            nas5G_element_location = getNASmessageLocation(NGAP_pdu)
                            nas5G_pdu, err = parse_NAS5G(nas5G_element_from_ngap._val)
                            if err != 0:
                                logger.error(f"NAS5G message could not be parsed. Error code : {err}")
                                raise ParseException(f"NAS5G message could not be parsed. Error code : {err}")
                            
                            # Create and fuzz NAS5G part of the packet
                            packet:Packet = Packet(pdu=nas5G_pdu, data=nas5G_element_from_ngap._val.hex(), configuration=configuration)
                            fuzzed_packet = fuzzer_engine.fuzzPacket(packet)
                            fuzzed_nas5G_message = fuzzed_packet.pdu.to_bytes()
                            NGAP_pdu.set_val_at(nas5G_element_location, fuzzed_nas5G_message)
                            output_raw_data = NGAP_pdu.to_aper()

                        # Add pdu_output to packet. This whole zone is mostly for development and debugging purposes.
                        #old_ngap_data = wr_packet.ngap_raw._fields_dict
                        #wr_packet.ngap_raw._fields_dict = output_raw_data.hex()
                        output_hex_data = output_raw_data.hex()
                        total_raw_packet = wr_packet.sll_raw._fields_dict + wr_packet.ip_raw._fields_dict + wr_packet.sctp_raw._fields_dict + output_hex_data + "00"
                        # Something interesting : sometimes, due to fuzzing a specific (unknown) field, the length of the whole packet is reduced from
                        # 360 hexchars to around 240. It might be interesting to find which specific field causes this.
                        if FLAG_DEBUGGING:
                            xored_string = xorHexStrings([total_raw_packet, wr_packet.frame_raw._fields_dict])
                            printBeautifiedHexString(xored_string)
                        
                        
                        #scapy_pkt = Ether(wr_packet.raw_bytes())
                        #sendp(Raw(total_raw_packet), iface="lo")

                        # Buffer is comma-separated string of following format:
                        # protocol, seed, message type value, length of the message, mask of the fuzzed values (old^new),
                        # packet (as a hex string), hw of mask, AMF response, label
                        line_buffer = fuzzing_protocol_name+", "
                        line_buffer += str(fuzzer_engine.seed)+", "
                        try:
                            line_buffer += str(NGAP_pdu.get_val_at(["initiatingMessage","procedureCode"]))+", "# Should always be present.
                        except Exception as e:
                            logger.warning(e)
                            line_buffer += "-1, "
                        mask = xorHexStrings([output_hex_data, wr_packet.ngap_raw._fields_dict])
                        line_buffer += str(len(output_hex_data)//2)+", " #In bytes
                        line_buffer += mask+", "
                        line_buffer += output_hex_data+", "
                        line_buffer += str(hamming_weight(mask)) + "\n"

                        with open(configuration["Output"]["outputFilename"], "a+") as stream:
                            stream.write(line_buffer)
                        

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
