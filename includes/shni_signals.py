#signal handler for shni
import os

def interrupt_handler(signum, frame):
    print("Custom interrupt detected...Function will be stopped shortly...")

