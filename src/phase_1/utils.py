
def create_label_vector(slither_results):
    """
    """

    # the vulnerabilities to look at
    relevant_vulnerabilities = [
        'reentrancy-eth',
        'reentrancy-no-eth',
    ]

    # label vector will be the size of the relevant vulnera
    label_vector = [0.0 for i in range(len(relevant_vulnerabilities))]
    if len(slither_results) > 0:
        detected = [d['check'] for d in slither_results['detectors'] if slither_results.get('detectors')]
        for i in range(len(relevant_vulnerabilities)):
            # if vulnerability was detected set to 1
            if relevant_vulnerabilities[i] in detected:
                label_vector[i] = 1.0
    
    return label_vector



def generate_unique_bigrams():
    """
    Create all possible unique bigrams to be used as the features. 
    Opcodes are significantly simplified to avoid the curse of diminsionality.
    """
    # iterate over all possible opcodes
    opcodes = ["_"]
    for i in range(0,256):
        opcode = simplify_opcode(i)
        if opcode:
            opcodes.append(opcode)
    
    # create all possible combinations of simplified bigrams
    all_possible_bigrams = set()
    for i in opcodes:
        for j in opcodes:
            all_possible_bigrams.add((i,j))
            
    return all_possible_bigrams
    
         
def create_feature_vector(bigrams):
    """
    Create feature space for training the model. Each feature value in a feature
    vector is the ratio of the bigram in the contract (decimal between 0 and 1)
    """
    unique_bigrams = generate_unique_bigrams()
    
    feature_vector = []
    for bigram in unique_bigrams:
        if len(bigrams) == 0:
            feature_value = 0
        else:
            feature_value = float(bigrams.count(bigram) / len(bigrams))
        feature_vector.append(feature_value)

    return feature_vector

def generate_opcodes(bytecode):
    opcodes = []
    # convert bytecode to opcodes
    for i in range(2, len(bytecode), 16):
        opcode = int(bytecode[i: i+2], 16)
        opcode = simplify_opcode(opcode)
        if opcode: # simplify opcode
            opcodes.append(opcode)
    
    return opcodes

def create_bigrams(opcodes):
    """
    Input: list of opcode strings
    Output: List of pairs of opcodes (digrams)
    """

    bigrams = []
    last_opcode = "_"
    n = len(opcodes)
    for i, opcode in enumerate(opcodes):
        if i+1 == n:
            bigram = (last_opcode, "_")
        else:
            bigram = (last_opcode, opcode)

        bigrams.append(bigram)
        last_opcode = opcode

    return bigrams

def simplify_opcode(opcode):
    """
    Extract relevant opcodes from the list of opcodes
    """
    # extract relevant opcodes
    if opcode in range(1,12): # 0x01 - 0x0b
        return 'ARITHMETIC_OP'
    elif opcode in range(16,21): # 0x10 - 0x15
        return 'COMPARISON'
    elif opcode in range(22,25): # 0x16 - 0x20
        return 'LOGIC_OP'
    elif opcode in range(48,52): # 0x30 - 0x33
        return 'CONSTANT1'
    elif opcode in range(64,71): # 0x40 - 0x46
        return 'CONSTANT2' # constants that have to do with block state
    elif opcode in range(96,128): # 0x60 - 0x7f
        return 'PUSH'
    elif opcode in range(128,144): # 0x80 - 0x8f
        return 'DUP'
    elif opcode in range(144,160): # 0x90 - 0x9f
        return 'SWAP'
    elif opcode in range(160, 165): # 0xa0 - 0xa4
        return 'LOG'
    

