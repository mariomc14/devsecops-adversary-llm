from argparse import ArgumentParser, ArgumentTypeError
import random
import sys
import json


import subprocess
import os
import shutil

def find_changes(input_file):
    file1 = open(input_file, 'r')

    alert_states = json.load(file1)
    res = True
    message = "Steady State validated"
    for state in alert_states:
        vals = alert_states[state]
        if not vals["Critical"]:
            res = False
            message = "Failed validation"
        if not vals["High"]:
            res = False
            message = "Failed validation"

    print(f"Is Steady State validated?: {res}")
    print(message)
    return res