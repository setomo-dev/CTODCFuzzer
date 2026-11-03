import os
import sys
import logging
import pathlib
import subprocess
import threading
import time
import signal
import atexit
import datetime
import json

import math
import random
import traceback

from abc import abstractmethod
from pathlib import Path
from typing import Dict, List, Optional
from cgroupspy import trees
from collections import defaultdict


from . import cgroup_utils, cli
from . import config as Config
from . import fuzzer_driver, sync, evaluator, thompson 
from .common import nested_dict, IS_PROFILE, IS_DEBUG
from .singleton import SingletonABCMeta

# set log file

logger = logging.getLogger('ctodcfuzzer.main')
logging.basicConfig(level=logging.INFO, filename='logCTODCFuzzer.log',filemode='w', format='%(filename)s-%(funcName)-10s-%(message)s')


LOG = nested_dict()

# Global variable
START_TIME: float = 0.0
config: Dict = Config.CONFIG
OUTPUT: Path
EVALUTOR_DIR : Path
INPUT: Optional[Path]
LOG_DATETIME: str
LOG_FILE_NAME: str

TIMEOUT: int
FOCUS_TIME: int
WEIGHT: int
TOPK: int
START_TIME:float = 0.0

SLEEP_GRANULARITY: int = 60

RUNNING: bool = False

FUZZERS: List[str]= []
TARGET: str
CPU_ASSIGN: Dict[str, float] = {}
CGROUP_ROOT = ''

ARGS: cli.ArgsParser

def terminate_ctodcfuzzer():
    global CTODCFUZZER_PID
    logger.critical('terminate ctodcfuzzer because of error')
    cleanup(1)

def is_end():
    logger.info('main 900 - check end time')
    global START_TIME
    diff = 60
    current_time = time.time()
    elasp = current_time - START_TIME
    timeout_seconds = TIMEOUT
    logger.info(f'elasp : {elasp}, timeout_seconds :{timeout_seconds}, current_time : {current_time}, START_TIME : {START_TIME} ')
    return elasp >= timeout_seconds + diff



def check_fuzzer_ready_one(fuzzer):
    global ARGS, FUZZERS, TARGET, OUTPUT
    ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
    if not os.path.exists(ready_path):
        return False
    return True

def sleep(seconds: int, log=False):
    logger.info(f'sleep time: {seconds}, log: {log}')
    global SLEEP_GRANULARITY
    if log:
        logger.info(f'sleep {seconds} seconds')
    else:
        logger.debug(f'sleep {seconds} seconds')
    remain = seconds
    while remain and not is_end():
        t = min(remain, SLEEP_GRANULARITY)
        time.sleep(t)
        remain -= t

def gen_fuzzer_driver_args(fuzzer: str,
                           jobs=1,
                           input_dir=None,
                           ) -> dict:
    global ARGS, CGROUP_ROOT

    fuzzer_config = config['fuzzer'][fuzzer]
    target_config = config['target'][TARGET]

    seed = None
    if input_dir:
        seed = input_dir
    else:
        seed = target_config['seed']
    group = target_config['group']
    target_args = target_config['args'].get(fuzzer, target_config['args']['default'])

    root_dir = os.path.realpath(ARGS.output)
    output = os.path.join(root_dir, TARGET, fuzzer)
    cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs,
        'cgroup_path': cgroup_path
    }
    return kw

def start(fuzzer: str, output_dir, timeout, input_dir=None):
    global FUZZERS,ARGS, TARGET

    fuzzer_config = config['fuzzer'][fuzzer]
    create_output_dir = fuzzer_config.get('create_output_dir',True)
    if create_output_dir:
        host_output_dir = f'{output_dir}/{TARGET}/{fuzzer}'
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{TARGET}'
        if os.path.exists(f'{output_dir}/{TARGET}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{TARGET}/{fuzzer}')
            terminate_ctodcfuzzer()
        os.makedirs(host_output_dir, exist_ok=True)
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'start'

    fuzzer_driver.main(**kw)

def pause(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to pause fuzzer
    '''
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)
    kw['command'] = 'pause'

    fuzzer_driver.main(**kw)

def resume(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to resume fuzzer
    '''    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, jobs=1, input_dir=input_dir)
    kw['command'] = 'resume'

    fuzzer_driver.main(**kw)

def stop(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to stop fuzzer
    '''  
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,jobs=1, input_dir=input_dir)
    kw['command'] = 'stop'

    fuzzer_driver.main(**kw)


# sync the seed and remove depulicated seed 
def do_sync(fuzzers: List[str], host_root_dir: Path, topk: int) -> bool:
    logger.info('Start seed sync')
    logger.info(f'TARGET : {TARGET}, fuzzers : {fuzzers}, host_root_dir : {host_root_dir}, topk : {topk}')

    start_time = time.time()    

    sync.sync2(TARGET, fuzzers, host_root_dir, topk)

    end_time = time.time()
    diff = end_time - start_time

    if IS_PROFILE: logger.info(f'main 111 - sync take {diff} seconds')
    logger.info('End seed sync')
    return True

def set_fuzzer_cgroup(fuzzer, new_cpu):
    global CGROUPR_ROOT
    
    p = os.path.join('/cpu', CGROUP_ROOT[1:], fuzzer)

    t = trees.Tree()
    
    fuzzer_cpu_node = t.get_node_by_path(p)

    cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us

    quota = int(cfs_period_us * new_cpu)

    if quota < 1000:
        quota = 1000
    logger.debug(f'set fuzzer cgroup {fuzzer} {new_cpu} {quota}')

    fuzzer_cpu_node.controller.cfs_quota_us = quota


def update_fuzzer_limit(fuzzer, new_cpu):
    global ARGS, CPU_ASSIGN, INPUT

    if fuzzer not in CPU_ASSIGN: return

    if math.isclose(CPU_ASSIGN[fuzzer], new_cpu):
        return

    is_pause = math.isclose(0, new_cpu)

    if is_pause:        
        pause(fuzzer=fuzzer, jobs=1, input_dir=INPUT)

    if math.isclose(CPU_ASSIGN[fuzzer], 0) and new_cpu != 0:
        resume(fuzzer=fuzzer, jobs=1, input_dir=ARGS.input)  

    CPU_ASSIGN[fuzzer] = new_cpu

    # setup cgroup
    if not is_pause:
        set_fuzzer_cgroup(fuzzer, new_cpu)
    else:
        set_fuzzer_cgroup(fuzzer, 0.01)

def cleanup(exit_code=0):
    global ARGS

    logger.info('Cleanup')

    LOG['end_time'] = time.time()

    write_log()

    for fuzzer in FUZZERS:
       stop(fuzzer)

    os._exit(exit_code)

def cleanup_exception(etype, value, tb):
    logger.critical("Uncaught exception", exc_info=(etype, value, tb))
    cleanup(1)

def write_log():
    global LOG, RUNNING
    if not RUNNING:
        logger.info('Not RUNNING, No log')
        return

    if OUTPUT and LOG_FILE_NAME:
        with open(f'{OUTPUT}/{LOG_FILE_NAME}', 'w') as f:
            f.write(json.dumps(LOG, default=json_dumper))
    else:
        assert False, 'update_log error'

def init():
    global START_TIME, LOG
    signal.signal(signal.SIGTERM, lambda x, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, frame: sys.exit(0))
    atexit.register(cleanup)
    sys.excepthook = cleanup_exception
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    pathlib.Path(health_check_path).touch(mode=0o666, exist_ok=True)
    LOG['log'] = []
    LOG['round'] = []
    logger.info(f'Init end')

def init_cgroup():
    logger.info(f'Cgroup init start')

    global FUZZERS, CGROUP_ROOT
    
    cgroup_path = cgroup_utils.get_cgroup_path()
    container_id = os.path.basename(cgroup_path)
    cgroup_path_fs = os.path.join('/sys/fs/cgroup/cpu', cgroup_path[1:])
    ctodcfuzz_cgroup_path_fs = os.path.join(cgroup_path_fs, 'ctodcfuzzer')

    if not os.path.exists(ctodcfuzz_cgroup_path_fs):
        logger.critical(
            'ctodcfuzzer cgroup not exists. make sure to run /init.sh first')
        terminate_ctodcfuzzer()

    t = trees.Tree()
    p = os.path.join('/cpu', cgroup_path[1:], 'ctodcfuzzer')
    CGROUP_ROOT = os.path.join(cgroup_path, 'ctodcfuzzer')
    cpu_node = t.get_node_by_path(p)
    
    for fuzzer in FUZZERS:
        fuzzer_cpu_node = t.get_node_by_path(os.path.join(p, fuzzer))
        if not fuzzer_cpu_node:
            fuzzer_cpu_node = cpu_node.create_cgroup(fuzzer)
        cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
        quota = int(cfs_period_us * (1))
        fuzzer_cpu_node.controller.cfs_quota_us = quota

    logger.info(f'Cgroup init end')
    return True

def init_evaluate(output_dir):
    global EVALUTOR_DIR, TARGET
    logger.info(f'Evaluate init start {output_dir}')
    
    host_output_dir = f'{output_dir}/{TARGET}/score'

    if os.path.exists(f'{output_dir}/{TARGET}/score'):
        logger.error(f'Please remove {output_dir}/{TARGET}/score')
        terminate_ctodcfuzzer()

    os.makedirs(host_output_dir, exist_ok=True)
    EVALUTOR_DIR = host_output_dir

    logger.info(f'Evaluate init end')


def evaluate_score(fuzzer : str):
    global EVALUTOR_DIR, OUTPUT, TARGET
    
    fuzzer_dir = f'{OUTPUT}/{TARGET}/{fuzzer}/queue'

    max_results = evaluator.extract_score(fuzzer=fuzzer, seed=fuzzer_dir, output_dir=EVALUTOR_DIR, program=TARGET)

    logger.info(f'Evaluate {fuzzer} results : {max_results}')

    return max_results



class SchedulingAlgorithm(metaclass=SingletonABCMeta):
    @abstractmethod
    def __init__(self, fuzzers, ctodcFuzzers, focus=None, one_core=False, N=1):
        pass

    @abstractmethod
    def run(self):
        pass

class Schedule_Base(SchedulingAlgorithm):
    def __init__(self,
                 fuzzers: List[str],
                 ctodcFuzzers,
                 focus_time: int,
                 weight: int,
                 topk: int
                 jobs: int = 1):

        self.fuzzers = fuzzers
        self.ctodcFuzzers = ctodcFuzzers
        self.name = 'schedule_base'

        # to support multicore
        self.jobs = jobs

        self.round_num = 1
        self.round_start_time = 0
        self.first_round = True

        self.focus_time = focus_time
        self.focus_time_base = focus_time

        self.weight = weight
        self.topk = topk
        
        self.focus_time_round = 0

        self.sync_time = 0

        self.picked_times: Dict[Fuzzer, int]
        
    def run_one(self, run_fuzzer):
        assert run_fuzzer in self.fuzzers

        for fuzzer in self.fuzzers:
            new_cpu = 1 if fuzzer == run_fuzzer else 0
            update_fuzzer_limit(fuzzer, new_cpu)

        logger.debug(f'single one: {run_fuzzer}')

    def pre_round(self):
        pass

    def one_round(self):
        pass

    def post_round(self):
        pass

    def main(self):
        pass
    
    def pre_run(self) -> bool:
        logger.info(f"{self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"{self.name}: post_run")

class Schedule_Single(Schedule_Base):
    def __init__(self, fuzzers, single):
        self.fuzzers = fuzzers
        self.single = single
        self.round = 1
        self.name = f'Single_{single}'

    def one_round(self):
        logger.info(f'One_round start')
        self.run_one(self.single)
        sleep(60)        
    
    def main(self):
        logger.info(f'Single_fuzzer : {self.single}')
        while True:
            if is_end(): 
                return
            self.one_round()
            self.round+=1
        logger.info(f'End')

    def pre_run(self) -> bool:
        logger.info(f"Single fuzzer {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"Single fuzzer {self.name}: post_run")

class Schedule_CTODCFuzzer(Schedule_Base):
    def __init__(self, fuzzers, ctodcFuzzers, focus_time=300, weight=20, topk=10):
        super().__init__(
            fuzzers=fuzzers,
            ctodcFuzzers=ctodcFuzzers,
            focus_time=focus_time,
            weight=weight,
            topk=topk
        )
        self.name = f'CTODCFuzzer_{focus_time}'
        self.round = 1
        self.ctodcFuzzers = ctodcFuzzers      
        self.current_round_record = None

    def focus(self):
        global OUTPUT, LOG

        logger.info('Start focus phase')
        focus_start_time = time.time()

        for name in self.fuzzers:
            logger.info(
                'main 507 - round=%s fuzzer=%s prox_S=%s prox_F=%s '
                'dom_S=%s dom_F=%s',
                self.round,
                name,
                self.ctodcFuzzers[name].S,
                self.ctodcFuzzers[name].F,
                self.domFuzzers[name].S,
                self.domFuzzers[name].F,
            )

        # Thompson sampling-based directed fuzzer selection
        selected_fuzzer = thompson.selectFuzzer(self.ctodcFuzzers)

        logger.info('Round=%s selected_fuzzer=%s', self.round, selected_fuzzer )
           

        previous_prox_score = int(self.ctodcFuzzers[selected_fuzzer].score)
        previous_dom_covered = int(self.ctodcFuzzers[selected_fuzzer].dom)

        # Selected directed fuzzer execution
        self.run_one(selected_fuzzer)
        sleep(self.focus_time)

        update_fuzzer_limit(selected_fuzzer, 0)

        # Common-Target-Oriented-Evaluation
        evaluate_start_time = time.time()
        evaluate_results = evaluate_score(selected_fuzzer)
        evaluate_run_time = time.time() - evaluate_start_time

        new_prox_score = int(evaluate_results['max_prox_score'])
        new_dom_covered = int(evaluate_results['max_dom_covered'])

        if new_dom_covered > global_max_dom_covered:
            focus_success = True
        elif (new_dom_covered == global_max_dom_covered and new_prox_score > global_max_prox_score):
            focus_success = True
        else:
            focus_success = False

        thompson.updateFuzzerCount(self.ctodcFuzzers, selected_fuzzer, focus_success, weight)

        logger.info(
            'Round=%s focus_fuzzer=%s max_prox_score=%s '
            'max_dom_covered=%s evaluate_run_time=%s '
            'prev_prox_score=%s prev_dom_covered=%s '
            'prox_improved=%s dom_improved=%s focus_success=%s '
            'dS=%s dF=%s S_after=%s F_after=%s',
            self.round,
            selected_fuzzer,
            new_prox_score,
            new_dom_covered,
            evaluate_run_time,
            previous_prox_score,
            previous_dom_covered,
            prox_improved,
            dom_improved,
            focus_success,
            prox_feedback['dS'],
            prox_feedback['dF'],
            prox_feedback['S_after'],
            prox_feedback['F_after'],
        )

        do_sync(self.fuzzers, OUTPUT, topk)

        focus_end_time = time.time()
        focus_run_time = focus_end_time - focus_start_time

        logger.info(
            'Round=%s focus_start_time=%s focus_end_time=%s focus_run_time=%s',
            self.round,
            focus_start_time,
            focus_end_time,
            focus_run_time,
        )

    def main(self):
        prep_completed = True

        while True:
            if is_end():
                return
            
            logger.info('CTODCFuzzer round %s start', self.round)

            self.focus()
            logger.info('CTODCFuzzer round %s end', self.round)
            self.round += 1

    def pre_run(self) -> bool:
        logger.info(f"{self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"{self.name}: post_run")

def main():
    global ARGS, TARGET, FUZZERS, OUTPUT, INPUT, TIMEOUT, FOCUS_TIME, WEIGHT, TOPK
    global START_TIME, LOG_DATETIME, LOG_FILE_NAME
    global CPU_ASSIGN, RUNNING

    ARGS = cli.ArgsParser().parse_args()

    logger.info(f'main start - ARG(user set option) : {ARGS}\n')

    # option parsing
    TARGET = ARGS.target
    FUZZERS = ARGS.fuzzer
    OUTPUT = ARGS.output.resolve()
    TIMEOUT = ARGS.timeout
    FOCUS_TIME = ARGS.focus
    WEIGHT = ARGS.weight
    TOPK = ARGS.topk

    if ARGS.input:
        INPUT = ARGS.input.resolve()
    else:
        INPUT = None

    logger.info(f'Check ARG : target : {TARGET}, fuzzer : {FUZZERS}, output : {OUTPUT}, timeout : {TIMEOUT}, focus_time : {FOCUS_TIME}, weight : {WEIGHT}, topk : {TOPK}')

    # create output directory
    try:
        os.makedirs(OUTPUT, exist_ok=False)
    except FileExistsError:
        logger.error(f'remove {OUTPUT}')
        exit(1)
    
    START_TIME = time.time()
    current_time = time.time()
    init()
    LOG['ctodcfuzzer_args'] = ARGS.as_dict()  
    LOG['ctodcfuzzer_config'] = config
    LOG['start_time'] = current_time
    LOG['algorithm'] = None

    # setup cgroup
    init_cgroup()
    
    ctodcFuzzers = {}

    # setup each fuzzer
    for fuzzer in FUZZERS:
        logger.info(f'Warm up {fuzzer}')
        CPU_ASSIGN[fuzzer] = 0
        ctodcFuzzers[fuzzer] = thompson.fuzzer()

        # start each fuzzer in process
        start(fuzzer=fuzzer, output_dir = OUTPUT, timeout=TIMEOUT, input_dir=INPUT)
         

        time.sleep(1)
        start_time = time.time()
        while not check_fuzzer_ready_one(fuzzer):
            current_time = time.time()
            elasp = current_time - start_time
            if elasp > 180:
                logger.critical('fuzzers start up error')
                terminate_ctodcfuzzer()
  
        pause(fuzzer=fuzzer, jobs=1, input_dir=INPUT)
    
    # setup evaluate
    init_evaluate(output_dir=OUTPUT)
        

    LOG_DATETIME = f'{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}'
    LOG_FILE_NAME = f'{TARGET}_{LOG_DATETIME}.json'

    scheduler = None
    algorithm = None

    fuzzerNum = len(FUZZERS) 

    if fuzzerNum == 1:
        logger.info(f'Single_fuzzer : {FUZZERS[0]}')
        scheduler = Schedule_Single(fuzzers=FUZZERS, single=FUZZERS[0])
        algorithm = FUZZERS[0]
    else: 
        logger.info(f'Multi_fuzzer : {FUZZERS}, FOCUS_TIME :{FOCUS_TIME} ')
        scheduler = Schedule_CTODCFuzzer(fuzzers=FUZZERS, ctodcFuzzers=ctodcFuzzers, focus_time=FOCUS_TIME, weight=WEIGHT, topk=TOPK)
        algorithm = 'ctodcfuzzer'
    
    LOG['algorithm'] = algorithm

    RUNNING = True

    # Timer to stop all fuzzers
    logger.info(f'Algorithm : {algorithm}, scheduler: {scheduler}')

    scheduler.run()

    logger.info(f'Scheduler run end')

    LOG['end_time'] = time.time()

    write_log()
    logger.info(f'End program')
    cleanup(0)


if __name__ == '__main__':
    main()
