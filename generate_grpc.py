import os
import sys
from grpc_tools import protoc

def generate_grpc_code():
    """Generate gRPC code from proto files"""
    # Get the directory containing this script
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Proto files to compile
    proto_files = ['chat.proto', 'raft.proto']
    
    for proto_file in proto_files:
        # Check if proto file exists
        proto_path = os.path.join(root_dir, proto_file)
        if not os.path.exists(proto_path):
            print(f"Error: {proto_file} not found")
            continue
            
        # Generate Python code
        protoc.main([
            'grpc_tools.protoc',
            f'--proto_path={root_dir}',
            f'--python_out={root_dir}',
            f'--grpc_python_out={root_dir}',
            proto_path
        ])
        
        print(f"Generated gRPC code for {proto_file}")
        
if __name__ == '__main__':
    generate_grpc_code() 