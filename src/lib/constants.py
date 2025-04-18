# Debugging
FLAG_DEBUGGING = True

# Configuration file path
CONFIG_FILE = "src/config.toml"


# Values for packet management.
FUZZ_THEN_SEND_PACKET = 0
SEND_PACKET = 1
BLOCK_PACKET = 2
RAISE_ERROR = 3

# Parameters for filter rule checking.
MAX_KEY_LENGTH = 30
MAX_VALUE_LENGTH = 30
MAX_EXPRESSION_LENGTH = 100
UNSECURE_CHARACTERS = set('!@#$%^|&*()+{}:"<>?[];\'\\\",./`~ ')
UNSECURE_CHARACTERS_EXPRESSION = set('!@#$%^|&*+{}:"<>?[];\'\\\",./`~')

# References for protocol
NGAP_PROTOCOL = 0
NAS5G_PROTOCOL = 1

# Parameters for fuzzing engine
MAX_QUEUE_SIZE = 256
MAX_CORE_AMOUNT = 8