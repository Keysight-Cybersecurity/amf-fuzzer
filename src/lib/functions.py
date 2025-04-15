
# Imports from standard libraries
from typing import Iterator
import tomllib, os.path
from binascii import unhexlify

# Imports from downloaded libraries
from pycrate_asn1dir import NGAP # pycrate
from pycrate_mobile.NAS5G import * # pycrate
import pycrate_core.elt

# Import from local lib
from lib.constants import *

# Logging
import logging
logger = logging.getLogger(__name__)



def xorHexStrings(string_iter: Iterator[str]) -> str:
    """ 
    Returns the result of the xor operation over all hexadecimal strings in string_iter.
    Do note that the leading zeros will be stripped. An iterator with a single element will return this element.

    Args:
        string_iter: Any iterator containing the hexadecimal strings to xor.
    
    Returns:
        xored_output: hexadecimal string, obtained from the xor operation over all input strings.

    Raises:
        ValueError: in case input strings cannot be interpreted as hexadecimal.
    """
    xored_output:int = 0
    max_len = 0
    for string in string_iter:
        string:str
        try:
            if string[:2].lower() == "0x":
                string=string[2:]
            max_len = max(max_len,len(string))
            xored_output ^= int(string, 16)
        except ValueError as e :
            logger.error (f"functions.py > xorHexStrings : string {string} cannot be interpreted as hexadecimal.")
            raise e
    output_string = hex(xored_output)[2:]
    output_string = "0"*(max_len-len(output_string))+output_string # Add leading zeros.
    return output_string


# Returns absolute paths so that we can then use "set_val_at()" function to change the value we wanted.
# In case multiple paths match, all of them will be returned.
# This is NOT EFFICIENT (O(n*m)), but this is the only way to have a general function that can find this.
def returnPathsFromEndpoint(paths: Iterator, endpoint:str) -> list:
    """
    Returns the list of all paths to a given ressource, where the ressource "endpoint" is given by its name.
    
    Flaw:
        Do note that one endpoint can have multiple paths.
        eg. path1 = [a, b, c, d] and path2 = [e, d, f, g] both have d as endpoint, and so both the paths will be returned.
    
    Args:
        paths: Iterator of paths, where paths are of the form (path, value), and path is a non-empty list of values.
        endpoint: name of the element we are getting the path of.

    Returns:
        valid_paths: list of all paths that contain the endpoint name. Can be empty.
    """
    valid_paths:list[list] = []
    for path in paths:
        if endpoint in path[0]: # Actual path, path[1] is endpoint value. We could think about getting path[1] too if we wanted the value.
            valid_paths.append(path[0])
    
    return valid_paths


def getNASmessage(pdu:pycrate_core.elt.Element):
    """
    Extract the NAS message from a NGAP message.
    Args:
        pdu: the Protocol Description Unit of the NGAP message we want to extract the NAS message from.
    Returns:
        output: None if no NAS message present. Else, output the NAS message as a binary string.
    """
    output = None
    paths = returnPathsFromEndpoint(pdu.get_val_paths(),"NAS-PDU")
    if len(paths)!=0:
        output = pdu.get_val_at(paths[0])
    return output




def getConfiguration():
    """
    Extract the configuration from the .toml configuration file.
    
    Returns:
        output: A dictionnary of all configuration elements.
    
    Raises:
        FileNotFounfError: if file defined in lib.constants.CONFIG_FILE couldn't be found.
        Exception: if the configuration could not be parsed.
    """
    output:dict = None
    try:
        with open(CONFIG_FILE, "rb") as config_file:
            output=tomllib.load(config_file)
    except FileNotFoundError as e:
        logger.error(f" functions.py > getConfiguration : file {CONFIG_FILE} could not be found.")
        raise e
    except Exception as e:
        logger.error(f" functions.py > getConfiguration : configuration file could not be parsed.")
        raise e
    return output





# Watch out: no protection against loops from logic links !
def getAllInputFiles(path_list:list[str], flag_recursive_search:bool)->set[str]:
    """
    Gets the path of all files within a directory.

    Args:
        path_list: The list of all files / directories to search through.
        flag_recursive_search: if True, will return files within subdirectories too, recursively. Unknown behavior in case of smart links.
        
    Returns:
        output: set of strings that are paths to the files about to be read.

    Raises:
        FileNotFoundError: if at least one of the files in entry does not exist.
    """
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
        logger.error (f" functions.py > getAllInputFiles : File {path} could not be found. ",exc_info=True)
        raise e
    return output



def getPathsFromNAS5G(element:pycrate_core.elt.Envelope)->list[str]:
    """
    Traverse the envelopes recursively and return all paths from all endpoints.
    Paths are of the format (path, value) where path is a list of strings.

    Args:
        element: the root element of all envelopes to explore. Usually this is the output of the parse_NAS5G function.
    
    Returns:
        paths: list of all elements found in calls to this function on leafs of current envelope node.
    
    """
    paths:list = []
    try:
        if element.CLASS in ["Envelope","Alt"]:
            for next_item in element._content:
                next_item:pycrate_core.elt.Element
                if next_item.CLASS == 'Atom':
                    paths.append((next_item.fullname().split("."), next_item._val))
                elif next_item.CLASS in ['Envelope', 'Alt']:
                    paths+=getPathsFromNAS5G(next_item)
                else:
                    logger.warning(f"functions.py > getPathsFromNAS5G : Class {next_item.CLASS} not considered.")
        else:
            logger.debug(f"Class {element.CLASS} is not managed in getPathsFromNAS5G.")
    except AttributeError as e:
        logger.debug(f"Element does not have CLASS attribute : {e}")

    return paths




def unifiedPathFinder(data_container:NGAP.NGAP_PDU_Descriptions, protocol_type:str, packet):
    """
    MAY NEED MAJOR RECODING.
    Returns the paths of all elements found in packet. Content of packet is updated in data_container.

    Args:
        data_container: ngap pdu in which the content of packet is going to be stored.
        protocol_type: 'ngap' or 'nas-5gs' depending on protocol to be parsed.
        packet: extracted packet from pyshark.

    Returns:
        paths: in the format (list[str], value), paths to every endpoint in the structure of the protocol.

    Raises:
        Exception: raised if no NAS packet is contained in NGAP, if protocol is "nas-5g".

    """
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
                raise e

        case "nas-5gs": # Do note, this is for NAS message that are still containerized by NGAP
            try:
                unhexlified_string = unhexlify(packet.ngap_raw._fields_dict)
                data_container.from_aper(unhexlified_string)
                raw_original_message:bytes = getNASmessage(data_container)
                if raw_original_message is not None:
                    original_message, err = parse_NAS5G(raw_original_message)
                    assert not err
                    return getPathsFromNAS5G(original_message)
                else:
                    print("No NAS message.")
                    logger.warning("No NAS message in NGAP packet while in NAS branch, check functionality of pyshark brancher.")
            except Exception as e:
                raise e
        case _:
            logger.error("No function to retrieve paths of endpoints from filter_input.")
    return None