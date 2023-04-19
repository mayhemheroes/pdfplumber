#! /usr/bin/env python3
import io
from contextlib import contextmanager
from random import random

import atheris
import sys


import fuzz_helpers as fh

with atheris.instrument_imports(include=['pdfplumber', 'pdfminer']):
    import pdfplumber

# Exceptions
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.psparser import PSException


@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr

def TestOneInput(data):
    fdp = fh.EnhancedFuzzedDataProvider(data)
    try:
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=True) as fp, nostdout():
            pdf = pdfplumber.open(fp)
            (page for page in pdf.pages)
    except (PDFSyntaxError, PSException):
        return -1
    except Exception as e:
        # Handle all other exceptions that are NOT raised by the program
        if random() > 0.99:
            raise e
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
