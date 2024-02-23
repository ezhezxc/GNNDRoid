# gnndroid
 graph merging

## Envrioment Requirement:

    python 3.8
    networkx 2.5
    androguard 3.3.5
    radare2 4.2

## Usage:
1.Run the main.py script(see more configurations in the code):
    
    python src/main.py --maldir path_to_malware --gooddir 
    path_to_benign --output_path path_to_merged_graphs

Two new folders are generated in ./graphs and ./graphs_to_train
    
    # generated MRDG
    ./graphs/
    └── $input_dir_name
        ├── apk1.gml
        ├── apk2.gml
        ├── apk3.gml
        ├── ...
                  
    # generated FCGs
    ./graphs/
    └── $input_dir_name
        └── $apk_name
            ├── callgraph.gml
            ├── libbspatch.gml
            ├── libroot.gml
            ├── ...
