#!/usr/bin/python3

######################################################################################
######### | Discovering vulnerabilities in Python web applications |##################
######################################################################################

###Students:
# 92513-Mafalda Ferreira
# 92546-Rita Oliveira

import argparse
from cfg import *
from patterns import *
from policy import *
from output_vulnerabilities import *

def get_output_filename(program_name):
    return program_name.rsplit('.json', 1)[0] + '.output.json'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('program', 
                        help = "Input file containing the representation of a Python slice in the form of an AST.")
    parser.add_argument('patterns',
                        help = "Input file with vulnerability patterns.")
    args = parser.parse_args()

    # Control Flow Graph
    cfg = CFG(args.program)
    
    # Vulnerability Patterns
    patterns = Patterns(args.patterns)
    
    #Policy
    policy = list()
    for vp in patterns.patterns:
        policy.append(Policy(vp.sources))
    
    # Eval CFG nodes
    vulnerabilities = Vulnerabilities()
    cfg.eval(policy, patterns, vulnerabilities)
    
    # Write to file
    f = open(get_output_filename(args.program), "w")
    f.write(vulnerabilities.__repr__())
    f.close()
        
    


if __name__ == '__main__':
    main()
