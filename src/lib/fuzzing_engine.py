# Standard libraries
import multiprocessing
import random
from datetime import *
from math import log2
from queue import Empty, Full

# Imported libraries
from pycrate_asn1rt.utils import get_obj_at

# Local libraries
from lib.constants import *
from lib.functions import *

# Logging
import logging
import pickle
logger = logging.getLogger(__name__)
# Do not uncomment, as that would raise a pickling error.

hexvalues = "0123456789ABCDEF"
hw_hexvalues = { # Key is length of data in bits. Index x of associated list gives all hex values with a hamming weight of x.
    4:["0","1248","3569AC","7BDE","F"],
    3:["0","124","356","7"],
    2:["0","12","3"],
    1:["0","1"]
}

# ====================================================================================== #
#                                                                                        #
#                                 PACKET CLASS                                           #
#                                                                                        #
# ====================================================================================== #

class Packet():
    # Configuration should be none only on child creation.
    def __init__(self, data=None, pdu=None, configuration=None):
        self.originalPacket = self
        self.parentPacket = None
        self.childPacket = None

        if data==None and pdu==None: 
            logger.error(" fuzzing_engine > Packet.__init__() : Either data or pdu has to be given as argument in packet creation.")
            raise ValueError("Either data or pdu has to be given as argument in packet creation.")
        self.data = data #RAW
        self.pdu = pdu #PDU structure
        self.protocol = configuration["Middleware"]["protocol"] if configuration is not None else None

        self.hierarchyLevel = 0
        self.fuzzedFieldsLocation = None #then use get_obj_at(pdu, path) in order to access actual object.
        self.response = None

        if configuration is not None:
            self.__assignFieldsLocation(configuration)

    def __eq__(self, other):
        if isinstance(other, Packet):
            return self.data == other.data
        return False



    def __assignFieldsLocation(self, configuration):
        """
        Updates the fuzzedFieldsLocation attribute with the list of paths to the elements that we are fuzzing on.

        Args:
            self: the packet to update the information of.
            configuration: configuration of the program, obtained from functions.py > getConfiguration

        """
        locations = []
        fields_to_fuzz:list[str] = configuration["Middleware"]["Fuzzer"]["fields"]
        if self.pdu != None and self.fuzzedFieldsLocation == None:
            
            # TOO MUCH INDENTATION ! TODO Get rid of this horror
            if self.protocol == "ngap":
                paths = self.pdu.get_val_paths()
                for path in paths:
                    for field_to_fuzz in fields_to_fuzz:
                        if field_to_fuzz in path[0]: # path[0] is actual path, path[1] is endpoint value
                            locations.append(path[0])
                            break
                    #logger.warning(f"Path {path} wasn't found.")

            elif self.protocol == "nas-5gs":
                paths = getPathsFromNAS5G(self.pdu)
                for path in paths:
                    for field_to_fuzz in fields_to_fuzz:
                        if field_to_fuzz in path[0]: # path[0] is actual path, path[1] is endpoint value
                            locations.append(path[0])
                            break
                    #logger.warning(f"Path {path} wasn't found.")
            
            self.fuzzedFieldsLocation=locations if locations != [] else None
            if FLAG_DEBUGGING:
                self.fuzzedFieldsLocation = paths # To remove at one point TODO

    def createChild(self):
        childPacket = Packet(self.data, self.pdu)
        childPacket.originalPacket = self.originalPacket
        childPacket.parentPacket = self

        childPacket.hierarchyLevel = self.hierarchyLevel+1
        childPacket.fuzzedFieldsLocation = self.fuzzedFieldsLocation
        childPacket.protocol = self.protocol
        self.child_packet = childPacket
        return childPacket
    


# ====================================================================================== #
#                                                                                        #
#                                   FUZZING ENGINE CLASS                                 #
#                                                                                        #
# ====================================================================================== #

class FuzzerEngine(multiprocessing.Process):
    # If engineManager is not defined, assume single-thread.
    def __init__(self, configuration, engineManager=None, seed_addition=0):
        multiprocessing.Process.__init__(self)
        self.engineManager = engineManager # May need to be set as argument of run for multiprocessing.
        self.seed = configuration["Middleware"]["Fuzzer"]["seed"]
        
        # Generate a random seed. We could set it to None, but if we do this then we
        # don't know which state the pseudorandom generator is set to, which would
        # stop us from reproducing interesting behaviours.
        if self.seed == 0:
            self.seed = int.from_bytes(os.urandom(12))
        else:
            self.seed = self.seed + seed_addition

        # TODO proper input management.
        # Changed from comma-separated string to list of strings.
        self.fieldsToFuzz:str = configuration["Middleware"]["Fuzzer"]["fields"]
        # If we want to make the fuzzing engine multi-process compatible, then we need multiple independent random number generators.
        # The default random generator uses Marcenne's twister, which has good apparent randomness but is deterministic
        self.randomGenerator = random.Random()
        self.randomGenerator.seed(self.seed)

        self.defaultBehavior = configuration["Middleware"]["Fuzzer"]["defaultBehavior"]
        self.protocol = configuration["Middleware"]["protocol"]
        self.bitToggleRate = configuration["Middleware"]["Fuzzer"]["bitToggleRate"]

        self.id = seed_addition # Hacky but it works. Will be used later for multiprocessing.
        logger.info(f"Engine nr {self.id} with seed {self.seed} has been created at {datetime.now()}")

    # Doesn't run yet. Issue comes from weak referenced elements in the class.
    # A fork will be created specifically to work on multiprocessing.
    def run(self):
        logger = logging.getLogger(__name__)
        fuzzing_queue:multiprocessing.Queue = self.engineManager.fuzzingQueue
        network_queue:multiprocessing.Queue = self.engineManager.networkQueue
        flag_awaiting_network_queue = False

        logger.info(f"Engine nr {self.id} has been started at {datetime.now()}")

        while self.engineManager.flagRunEngines:
            try:
                if not flag_awaiting_network_queue:
                    packet_to_fuzz = fuzzing_queue.get(timeout = 3.0)
                    fuzzed_packet = self.fuzzPacket(packet_to_fuzz)
                network_queue.put(fuzzed_packet, timeout=3.0)
                flag_awaiting_network_queue = False
            except multiprocessing.Empty: # For the fuzzing queue
                continue
            except multiprocessing.Full: # For the networking queue
                flag_awaiting_network_queue = True
                continue
        logger.info(f"Engine nr {self.id} has been stopped at {datetime.now()}")
        return

    def fuzzPacket(self, packet:Packet)->Packet:
        pass

    def __fuzzRawData(self, data:str)->str:
        pass
        


    







class DumbFuzzingEngine(FuzzerEngine):
    def __init__(self, configuration, engineManager=None, seed_addition=0):
        super().__init__(configuration, engineManager, seed_addition)
    
    def run(self):
        pass

    def fuzzPacket(self, packet:Packet)->Packet:
        fuzzed_packet = packet.createChild()
        if fuzzed_packet.protocol == "ngap":
            if fuzzed_packet.fuzzedFieldsLocation is not None:
                assert fuzzed_packet.pdu is not None
                #elements_to_fuzz = [get_obj_at(fuzzed_packet.pdu,element_location) for element_location in fuzzed_packet.fuzzedFieldsLocation]
                elements_to_fuzz = [get_obj_at(fuzzed_packet.pdu,element_location[0]) for element_location in fuzzed_packet.pdu.get_val_paths()]
                # Fuzz here
                for element in elements_to_fuzz:
                    
                    print("New element")
                    try:
                        match element.TYPE: # This is ASN1 types
                            case "INTEGER":
                                element.set_val(self.__fuzzIntegersNGAP(element))
                            case "BIT STRING":
                                element.set_val(self.__fuzzBitStringNGAP(element))
                            case "ENUMERATED":
                                element.set_val(self.__fuzzEnumeratedNGAP(element))
                            case "OCTET STRING":
                                element.set_val(self.__fuzzOctetStringNGAP(element))
                            case "PrintableString":
                                logger.info(f"Element PrintableString with value {element._val} should have been fuzzed, but has not been due to implementation limits.")
                                pass # No idea what to do with this one.
                            case _:
                                logger.error(f"fuzzing_engine.py > DumbFuzzingEngine > fuzzPacket : element type {element.TYPE} is not managed.")
                                raise TypeError(f"fuzzing_engine.py > DumbFuzzingEngine > fuzzPacket : element type {element.TYPE} is not managed.")
                    except Exception as e:
                        logger.error(e)
                        raise e
                
            
            # Use raw data. It's easier.
            elif self.defaultBehavior == "fuzzwholepacket":
                fuzzed_packet.data = self.__fuzzRawData(fuzzed_packet.data)

            else:
                logger.debug(f"Default behavior {self.defaultBehavior} is unknown.")
                pass


            # End of fuzzing
        elif fuzzed_packet.protocol == "nas-5gs":
            assert fuzzed_packet.pdu is not None
            if fuzzed_packet.fuzzedFieldsLocation is not None: # This is 5GMM structure.
                for location in fuzzed_packet.fuzzedFieldsLocation:
                    element = getObjAt5GMM(fuzzed_packet.pdu, location[0])

                    if int in element.TYPES:
                        element.set_val(self.__fuzzIntegersNAS5G(element))
                    elif bytes in element.TYPES:
                        element.set_val(self.__fuzzBytesNAS5G(element))
                    else:
                        logger.error(f"fuzzing_engine.py > DumbFuzzingEngine > fuzzPacket : element type {element.TYPES} is not managed.")
                        raise TypeError(f"fuzzing_engine.py > DumbFuzzingEngine > fuzzPacket : element type {element.TYPES} is not managed.")

            elif self.defaultBehavior == "fuzzwholepacket":
                fuzzed_packet.data = self.__fuzzRawData(fuzzed_packet.data)

            else:
                logger.debug(f"Default behavior {self.defaultBehavior} is unknown.")
                pass
                
        else:
            logger.debug(f"Protocol {fuzzed_packet.protocol} unknown.")
            pass

        return fuzzed_packet
    


    
    
    def __fuzzRawData(self, data:str)->str:
        hex_length = len(data)
        mask = ""
        for i in range(hex_length):
            mask = mask+self.randomGenerator.choice(hw_hexvalues[4][self.randomGenerator.binomialvariate(4,self.bitToggleRate)])
        return xorHexStrings([data,mask])
    

    def __fuzzIntegersNAS5G(self, element) -> int:
        if element._val == None:
            logger.info(f"Element {element._name} is of type int but has value of type {type(element._val)}. Ignoring.")
            return element._val
        int_value = element._val
        lb = element._get_val_min()
        ub = element._get_val_max()
        bits = element._bl
        mask = ""
        while bits >= 4:
            hex_value_choices = hw_hexvalues[4][self.randomGenerator.binomialvariate(4,self.bitToggleRate)]
            mask += self.randomGenerator.choice(hex_value_choices)
            bits-=4
        if bits > 0:
            hex_value_choices = hw_hexvalues[bits][self.randomGenerator.binomialvariate(bits,self.bitToggleRate)]
            # We aggregate the new hex char first instead of mask because we don't want the resulting int value to get out of bounds.
            mask = self.randomGenerator.choice(hex_value_choices) + mask
        return int(xorHexStrings([hex(int_value),mask]),16)
    

    # TODO resolve whatever is going on in here.
    def __fuzzBytesNAS5G(self, element) -> bytes:
        if type(element._val)!=bytes:
            logger.warning(f"Element {element._name} is of type int but has value of type {type(element._val)}.")
            return element._val
        elif type(element._bl) != int or element._bl < 4:
            logger.warning(f"Element {element._name} is in PDU but has bit length < 4. Bit length >=8 expected.")
            return element._val
        hex_output = self.__fuzzRawData(element._val.hex())
        return bytes.fromhex(hex_output)


    
    def __fuzzIntegersNGAP(self, element) -> int:
        int_value = element._val
        lb = element._const_val.lb
        ub = element._const_val.ub
        assert ub > lb, "ub <= lb"
        ra = ub - lb + 1
        bits = int(log2(ra))
        mask = ""
        while bits >= 4:
            hex_value_choices = hw_hexvalues[4][self.randomGenerator.binomialvariate(4,self.bitToggleRate)]
            mask += self.randomGenerator.choice(hex_value_choices)
            bits-=4
        if bits > 0:
            hex_value_choices = hw_hexvalues[bits][self.randomGenerator.binomialvariate(bits,self.bitToggleRate)]
            # We aggregate the new hex char first instead of mask because we don't want the resulting int value to get out of bounds.
            mask = self.randomGenerator.choice(hex_value_choices) + mask
        return int(xorHexStrings([hex(int_value),mask]),16)
    
    # Bitstrings are 2-tuple. Index 0 is the value, index 1 is the length in bits of the value.
    # For example, (x,y) would indicate that the value x is represented over y bits.
    # If r = y%8, then x is padded by r bits on its LSBs.
    def __fuzzBitStringNGAP(self, bitstring_element):
        value = bitstring_element._val[0]
        bits = bitstring_element._val[1]
        mask = ""
        while bits >= 4:
            hex_value_choices = hw_hexvalues[4][self.randomGenerator.binomialvariate(4,self.bitToggleRate)]
            mask += self.randomGenerator.choice(hex_value_choices)
            bits-=4
        if bits != 0:
            hex_value_choices = hw_hexvalues[bits][self.randomGenerator.binomialvariate(bits,self.bitToggleRate)]
            # We aggregate the new hex char first instead of mask because we don't want the resulting int value to get out of bounds.
            mask = self.randomGenerator.choice(hex_value_choices) + mask
        return (int(xorHexStrings([hex(value),mask]),16), bitstring_element._val[1])
    
    def __fuzzEnumeratedNGAP(self, element):
        choices = element._cont_rev
        flag_fuzz = (self.randomGenerator.randint(0,100) < int(self.bitToggleRate)*100)
        if flag_fuzz:
            return choices[self.randomGenerator.randint(0,len(choices))]
        else:
            return element._val
        
    def __fuzzOctetStringNGAP(self, element):
        hex_output = self.__fuzzRawData(element._val.hex())
        return bytes.fromhex(hex_output)



class MultiEngineManager():
    
    def __init__(self, configuration):

        
        self.fuzzerEngineClass = FuzzerEngine
        match configuration["Middleware"]["Fuzzer"]["fuzzerEngine"]:
            case "dumb":
                logger.info(f"{configuration["Middleware"]["Fuzzer"]["fuzzerEngine"]} Still not implemented.")
                self.fuzzerEngineClass = DumbFuzzingEngine
                pass
            case "mutation":
                logger.info(f"{configuration["Middleware"]["Fuzzer"]["fuzzerEngine"]} Still not implemented.")
                pass
            case "afl":
                logger.info(f"{configuration["Middleware"]["Fuzzer"]["fuzzerEngine"]} Still not implemented.")
                pass

        self.queueSize = configuration["Middleware"]["Multiprocessing"]["queueSize"]
        self.enginesAmount = configuration["Middleware"]["Multiprocessing"]["coreAmount"]
        self.flagRunEngines = False
        if self.queueSize > MAX_QUEUE_SIZE or self.enginesAmount > MAX_CORE_AMOUNT:
            raise Exception

        self.fuzzingQueue = multiprocessing.Queue(self.queueSize)
        self.networkQueue = multiprocessing.Queue(self.queueSize)
        self.managedEngines = [self.fuzzerEngineClass(configuration, self, seed_addition=i) for i in range(self.enginesAmount)]

    def startAll(self):
        self.flagRunEngines = True
        logger.info(f"Starting {self.enginesAmount} {self.fuzzerEngineClass} engines.")
        for engine in self.managedEngines:
            try:
                pickle.dumps(engine)
                engine.start()
            except Exception as e:
                print(e)
                
    
    def killAll(self):
        self.flagRunEngines = False
        for engine in self.managedEngines:
            engine.kill()

    def joinAll(self):
        self.flagRunEngines = False
        for engine in self.managedEngines:
            engine.join()
