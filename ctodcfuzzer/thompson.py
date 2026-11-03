import logging
from typing import Dict, Iterable, List, Optional

import numpy as np

logger = logging.getLogger('ctodcfuzzer.thompson')


class fuzzer():
    def __init__(self):
        self.S = 1  # success count
        self.F = 1  # fail count
        self.prob = 0.0  # beta sample used for the latest selection
        self.total_runTime = 0
        self.score = 0  # prox_score
        self.dom = 0  # dom_covered

def selectFuzzer(ctodcFuzzers):
    for fuzzer in ctodcFuzzers.values():
        fuzzer.prob = np.random.beta(fuzzer.S, fuzzer.F)
    return max( ctodcFuzzers,  key=lambda name: ctodcFuzzers[name].prob )


def updateFuzzerCount(ctodcfuzzer, selected_fuzzer, criteria, weight: int = 20):

    selected = ctodcfuzzer[selected_fuzzer]
    before_s = int(selected.S)
    before_f = int(selected.F)

    if criteria :
        selected.S += weight
        outcome = 'success'
        dS, dF = weight, 0
    else:
        selected.F += delta
        outcome = 'fail'
        dS, dF = 0, weight

    logger.info(
        'thomps 003 - fuzzer=%s outcome=%s dS=%s dF=%s '
        'S_before=%s F_before=%s S_after=%s F_after=%s',
        selected_fuzzer, outcome, dS, dF, before_s, before_f, selected.S, selected.F)
