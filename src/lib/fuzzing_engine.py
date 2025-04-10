# Standard libraries
import queue
import multiprocessing
from lib.constants import *
from lib.functions import *
from pycrate_asn1rt.utils import get_obj_at

# Logging
import logging
logger = logging.getLogger(__name__)


class Packet():
    def __init__(self, data=None, pdu=None):
        self.originalPacket = self
        self.parentPacket = None
        self.childPacket = None

        if data==None and pdu==None: 
            logger.error(" fuzzing_engine > Packet.__init__() : Either data or pdu has to be given as argument in packet creation.")
            raise ValueError("Either data or pdu has to be given as argument in packet creation.")
        self.data = data #RAW
        self.pdu = pdu #PDU structure

        self.hierarchyLevel = 0
        self.fuzzedFieldsLocation = None
        self.response = None

    def createChild(self):
        childPacket = Packet(self.data, self.pdu)
        childPacket.originalPacket = self.originalPacket
        childPacket.parentPacket = self

        childPacket.hierarchyLevel = self.hierarchyLevel+1
        childPacket.fuzzedFieldsLocation = self.fuzzedFieldsLocation
        self.child_packet = childPacket
        return childPacket
    

    

class FuzzerEngine(multiprocessing.Process):
    # If engineManager is not defined, assume single-thread.
    def __init__(self, configuration, engineManager=None):
        multiprocessing.Process.__init__(self)
        self.engineManager = engineManager

        # TODO proper input management.
        self.fieldsToFuzz:str = configuration["Middleware"]["Fuzzer"]["fields"].replace(" ", "").split(",")
        self.seed = configuration["Middleware"]["Fuzzer"]["seed"]
        self.defaultBehavior = configuration["Middleware"]["Fuzzer"]["defaultBehavior"]
        self.protocol = configuration["Middleware"]["protocol"]

    def run(self):
        pass

    def fuzzPacket(self, packet:Packet)->Packet:
        pass

    def assignPacketFields(self, packet:Packet):
        locations = []
        fields = []
        if packet.pdu != None and packet.fuzzedFieldsLocation == None:
            
            # TOO MUCH INDENTATION ! TODO Get rid of this horror
            if self.protocol == "ngap":
                paths = packet.pdu.get_val_paths()
                for path in paths:
                    for field_to_fuzz in self.fieldsToFuzz:
                        if field_to_fuzz in path[0]: # path[0] is actual path, path[1] is endpoint value
                            locations.append(path[0])

            elif self.protocol == "nas-5gs":
                paths = flattenNas5GTreeRecursiveEnvelopeTraversal(packet.pdu)
                for path in paths:
                    for field_to_fuzz in self.fieldsToFuzz:
                        if field_to_fuzz in path[0]: # path[0] is actual path, path[1] is endpoint value
                            locations.append(path[0])
            
            # Broken
            for location in locations:
                fields.append(get_obj_at(packet.pdu,location))


        return fields
            # We have to find a way to differentiate if we parse asn1 or something else


    

class DumbFuzzingEngine(FuzzerEngine):
    def __init__(self, configuration, engineManager=None):
        super().__init__(configuration, engineManager)
    
    def run(self):
        pass

    def fuzzPacket(self, packet):
        # For now, assume no fields targeted. We're just going to fuzz the raw data.
        fuzzed_packet = packet.createChild()
        
        





class MultiEngineManager():
    
    def __init__(self, configuration, fuzzerClass):

        self.queueSize = configuration["Middleware"]["Multiprocessing"]["queueSize"]
        self.enginesAmount = configuration["Middleware"]["Multiprocessing"]["coreAmount"]
        assert type(self.queueSize) == int and self.queueSize <= MAX_QUEUE_SIZE
        assert type(self.enginesAmount) == int and self.enginesAmount <= MAX_CORE_AMOUNT

        self.packetQueue = queue.Queue(MAX_QUEUE_SIZE)
        self.managedEngines = [FuzzerEngine(configuration, self) for i in range(self.enginesAmount)]

    def startAll(self):
        for engine in self.managedEngines:
            engine.start()
    
    def killAll(self):
        for engine in self.managedEngines:
            engine.kill()

    def joinAll(self):
        for engine in self.managedEngines:
            engine.join()