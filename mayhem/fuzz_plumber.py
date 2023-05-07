#! /usr/bin/env python3
import io
from contextlib import contextmanager

import atheris
import sys

import fuzz_helpers as fh

with atheris.instrument_imports(include=['pdfplumber', 'pdfminer']):
    import pdfplumber

# Exceptions
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.psparser import PSException


ctr = 0

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
    global ctr
    fdp = fh.EnhancedFuzzedDataProvider(data)

    ctr += 1
    try:
        choice = fdp.ConsumeIntInRange(0, 2)
        with fdp.ConsumeMemoryFile(all_data=True, as_bytes=True) as fp, nostdout():
            pdf = pdfplumber.open(fp)
            if choice == 0:
                [page for page in pdf.pages]
            elif choice == 1:
                if pdf.pages:
                    pdf.pages[0].extract_table()
            elif choice == 2:
                pdfplumber.pages[0].to_image()
    except (PDFSyntaxError, PSException):
        return -1
    except Exception:
        # Handle all other exceptions that are NOT raised by the program
        if ctr > 100_000:
            raise

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
