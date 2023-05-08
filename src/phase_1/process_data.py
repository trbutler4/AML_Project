from utils import create_feature_vector, create_bigrams, generate_opcodes, create_label_vector
import json

def process(ds):
    
    ds = ds.flatten()
    
    # remove unneeded data
    ds = ds.remove_columns('address')
    ds = ds.remove_columns('source_code')
    
    print(f"processing training data...") 
    train_ds = ds['train'].map(process_row, load_from_cache_file=False)

    print(f"processing test data...") 
    test_ds = ds['test'].map(process_row, load_from_cache_file=False)

    
    # set to pytorch format 
    train_ds.set_format(type='torch', columns=['features', 'labels'])
    test_ds.set_format(type='torch', columns=['features', 'labels'])
    
    # save to disk
    train_ds.save_to_disk("data/train")
    test_ds.save_to_disk("data/test")
    

    return train_ds, test_ds


def process_row(row):
    bytecode = row['bytecode']

    # generate opcodes
    opcode = generate_opcodes(bytecode)

    # generate bigrams
    opcode_bigrams = create_bigrams(opcode)
    row['bigrams'] = opcode_bigrams
    
    # create feature vector
    feature_vector = create_feature_vector(opcode_bigrams)
    row['features'] = feature_vector

    # create label vector
    slither_results = json.loads(row['slither'])['results']
    label_vector = create_label_vector(slither_results)
    row['labels'] = label_vector
    
    return row

