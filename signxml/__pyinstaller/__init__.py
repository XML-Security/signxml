"""
This file indicates that this directory contains the hooks to include the schema files on the final version
if it's compiled with pyinstaller.
"""

import os


def get_hook_dirs():
    return [os.path.dirname(__file__)]
