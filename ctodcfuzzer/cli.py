import os
import sys

from pathlib import Path
from tap import Tap
from typing import List, Optional

from . import config as Config

config = Config.CONFIG

class ArgsParser(Tap):
    input: Path
    output: Path
    fuzzer: List[str]
    target: str
    focus: int
    weight: int
    topk: int
    timeout: int
    focus_one: Optional[str]

    def configure(self):
        global config

        DEFAULT_FOCUS_TIME = config['scheduler']['focus_time']
        DEFAULT_WEIGHT= config['scheduler']['weight']
        DEFAULT_TOPK= config['scheduler']['sync_top_']
        available_fuzzers = list(config['fuzzer'].keys())
        available_targets = list(config['target'].keys())

        self.add_argument(
            "-i", "--input",
            required=False,
            help="Opyional input (seed) directory"
        )
        self.add_argument(
            "-o", "--output",
            required=True,
            help="an output directory"
        )

        self.add_argument(
            "-t", "--target",
            choices=available_targets,
            type=str,
            required=True,
            help="target bug site"
        )

        self.add_argument(
            "-f", "--fuzzer",
            nargs='+',
            choices=available_fuzzers,
            type=str,
            required=True,
            help="baseline fuzzers to include"
        )

        self.add_argument("--focus",
                type=int,
                default=DEFAULT_FOCUS_TIME,
                help="execution time (default=300)")
        
        self.add_argument(
                "-w", "--weight",
                type=int,
                default=DEFAULT_WEIGHT,
                help="execution time (default=20)")

        self.add_argument(
                "-k", "--topk",
                type=int,
                default=DEFAULT_TOPK,
                help="execution time (default=10)")            

        self.add_argument(
            "-T", "--timeout",
            type=int,
            default=86400,
            help="program termination time (default=86400(=24h))"
        )

        self.add_argument("--focus-one",
                default=None,
                help="Used to run a specific individual fuzzer.")

