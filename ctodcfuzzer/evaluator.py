import os
import re
import sys
from pathlib import Path
import shutil
import time
import logging
import subprocess
import peewee

from . import config as Config
from .evaluateDB import AFLGoSeed, WindRangerSeed, DAFLSeed, init_db


CONFIG = Config.CONFIG
SCORE_CONFIG = CONFIG['score_DAFL']
DAFL_CONFIG = CONFIG['fuzzer']['dafl']
DOMINATOR_CONFIG = CONFIG['dominator']

logger = logging.getLogger('ctodcfuzzer.evaluate')

# helper
def seed_id_num(name: str) -> int:
    m = re.search(r"id:(\d+)", name)
    if not m:
        return -1
    return int(m.group(1))


def safe_int(v, default=-1):
    return int(v) if v is not None else default




def gen_run_args(seed, output, program):
    global SCORE_CONFIG, DAFL_CONFIG, CONFIG

    logger.info("Start gen_run_args")

    args = []
    command = SCORE_CONFIG['command']

    target = DAFL_CONFIG['target_root']
    target_root = os.path.join(target, program)

    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']

    logger.info(f"Command : {command}, target_args : {target_args}, target_root : {target_root}")

    args += [command, '-i', seed, '-o', output]
    args += ['-m', 'none']
    args += ['-t', '10000+']
    args += ['-d']
    args += ['--', target_root]
    if target_args != '':
        args += target_args.split(' ')
    return args


def gen_dominator_args(seed_file: str, program: str):
    global DOMINATOR_CONFIG, CONFIG

    target_root = os.path.join(DOMINATOR_CONFIG['target_root'], program)
    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']

    args = [target_root]
    if target_args:
        for part in target_args.split(' '):
            if part == '@@':
                args.append(seed_file)
            else:
                args.append(part)
        if '@@' not in target_args.split(' '):
            args.append(seed_file)
    else:
        args.append(seed_file)

    logger.info(f"Dominator args : {args}")
    return args


def normalize_afl_seed_id(name: str) -> str:
    base = os.path.basename(name)

    m = re.search(r"((?:[a-zA-Z0-9]+_)?id:\d+)", base)
    if not m:
        raise ValueError(f"Invalid AFL seed name: {name}")

    return m.group(1)


def extract_afl_seed_id(line: str) -> str:
    _, rest = line.split(",", 1)
    base = os.path.basename(rest)

    m = re.search(r"((?:[a-zA-Z0-9]+_)?id:\d+)", base)
    if not m:
        raise ValueError(f"Cannot find seed id in line: {line}")

    return m.group(0)


def parse_score_file(path):
    parse_data = {}
    with open(path, "r") as f:
        lines = f.read().strip().splitlines()

    for line in lines[1:]:
        parts = line.split(",")

        prox_score = int(parts[-3])
        bitmap_size = int(parts[-1])

        name = extract_afl_seed_id(line)
        parse_data[name] = (prox_score, bitmap_size)
        logger.info(f"Name : {name}, parse_data : {parse_data[name]}")

    return parse_data


def parse_dom_covered(output: str):
    m = re.search(r"DOM_COVERED=(\d+)", output)
    if not m:
        logger.info(f"DOM_COVERED not found in output: {output}")
        return None
    return int(m.group(1))


def run_dominator_for_seed(seed_file: str, program: str):
    args = gen_dominator_args(seed_file=seed_file, program=program)
    log_path = f"{seed_file}.dom.log"

    try:
        with open(log_path, "wb") as logf:
            result = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=logf
            )
    except Exception:
        logger.exception(
            f"Subprocess.run failed, seed={seed_file}, args={args}"
        )
        raise

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        log_text = f.read()

    dom_covered = parse_dom_covered(log_text)

    logger.info(
        f"Dominator rc={result.returncode}, seed={seed_file}, dom_covered={dom_covered}"
    )

    return dom_covered if dom_covered is not None else 0


def evaluate_dom_covered_for_snapshot(snapshot_dir: str, program: str, alias_to_real=None):
    if alias_to_real is None:
        alias_to_real = {}

    dom_result = {}
    src = Path(snapshot_dir)

    for p in sorted(src.iterdir(), key=lambda x: x.name):
        if not p.is_file():
            continue
        if p.name.startswith('.') or p.name == 'README.txt':
            continue
        if '-sync' in p.name:
            continue
        if p.name.endswith('.dom.log'):
            continue

        alias_seed_id = normalize_afl_seed_id(p.name)
        real_seed_id = alias_to_real.get(alias_seed_id, alias_seed_id)

        dom_result[real_seed_id] = run_dominator_for_seed(seed_file=str(p), program=program)

        logger.info(
            f"Alias_seed_id={alias_seed_id}, real_seed_id={real_seed_id}, dom_covered={dom_result[real_seed_id]}"
        )

    return dom_result


def wait_for_file(path):
    wait_time = 0
    while not os.path.exists(path):
        wait_time += 1
        time.sleep(1)
        if wait_time == 600:
            logger.info('No exists')
            break


def cleanup_score_artifacts(score_file, snapshot_dir, score_workdir):
    if os.path.exists(score_file):
        try:
            os.remove(score_file)
        except Exception:
            pass

    if os.path.exists(snapshot_dir):
        shutil.rmtree(snapshot_dir, ignore_errors=True)

    if os.path.exists(score_workdir):
        shutil.rmtree(score_workdir, ignore_errors=True)


def get_seed_model(fuzzer: str):
    f = fuzzer.lower()
    if f == "aflgo":
        return AFLGoSeed
    if f == "windranger":
        return WindRangerSeed
    if f == "dafl":
        return DAFLSeed
    raise ValueError(f"Unknown fuzzer: {fuzzer}")

def snapshot_dir_incremental(fuzzer: str, src_queue: str, dst_dir: str):
    logger.info(f'Incremental snapshot: fuzzer={fuzzer}, src_queue={src_queue}, dst_dir={dst_dir}')

    SeedModel = get_seed_model(fuzzer)

    src = Path(src_queue)
    dst = Path(dst_dir)

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    staged_names = []
    alias_to_real = {}

    alias_idx = 0

    for p in sorted(src.iterdir(), key=lambda x: x.name):
        if not p.is_file():
            continue
        if p.name.startswith(".") or p.name == "README.txt":
            continue
        if p.name.endswith(".dom.log"):
            continue

        real_seed_id = normalize_afl_seed_id(p.name)

        if SeedModel.select().where(SeedModel.name == real_seed_id).exists():
            continue

        if "-sync" in p.name:
            logger.info(
                f"Skip sync seed without inheriting source score: {p.name}"
            )
            continue

        alias_seed_id = f"id:{alias_idx:06d}"
        alias_idx += 1

        shutil.copy2(p, dst / alias_seed_id)

        staged_names.append(real_seed_id)
        alias_to_real[alias_seed_id] = real_seed_id

        logger.info(
            f"Snapshot alias: "
            f"{alias_seed_id} -> {real_seed_id}, src={p.name}"
        )

    logger.info(
        f"Staged new seeds: {len(staged_names)}"
    )

    return staged_names, alias_to_real

def max_prox_from_db(fuzzer: str) -> dict:
    SeedModel = get_seed_model(fuzzer)

    prox_rows = list(
        SeedModel
        .select()
        .where(SeedModel.prox_score.is_null(False))
    )

    dom_rows = list(
        SeedModel
        .select()
        .where(SeedModel.dom_covered.is_null(False))
    )

    prox_row = max(
        prox_rows,
        key=lambda r: (
            safe_int(r.prox_score),
            safe_int(r.dom_covered),
            seed_id_num(r.name)
        ),
        default=None
    )

    dom_row = max(
        dom_rows,
        key=lambda r: (
            safe_int(r.dom_covered),
            safe_int(r.prox_score),
            seed_id_num(r.name)
        ),
        default=None
    )

    max_prox_score = safe_int(prox_row.prox_score) if prox_row else -1
    max_dom_covered = safe_int(dom_row.dom_covered) if dom_row else -1

    prox_seed_id = prox_row.name if prox_row else None
    dom_seed_id = dom_row.name if dom_row else None

    logger.info(f"Fuzzer={fuzzer} max_prox_score={max_prox_score}, prox_seed_id={prox_seed_id}")
    logger.info(f"Fuzzer={fuzzer} max_dom_covered={max_dom_covered}, dom_seed_id={dom_seed_id}")

    return {
        'max_prox_score': max_prox_score,
        'max_dom_covered': max_dom_covered
    }


def extract_score(fuzzer, seed, output_dir, program):
    logger.info(f'Fuzzer : {fuzzer}, seed : {seed}, output_dir : {output_dir}, program : {program}')

    seed_path = os.path.realpath(seed)
    output_path = os.path.realpath(output_dir)

    base_dir = "/home/ctodcfuzzer"
    score_path = os.path.join(base_dir, "initial_seed_scores.txt")

    os.makedirs(output_path, exist_ok=True)

    db_path = os.path.join(output_path, f"{fuzzer}.sqlite")
    database = peewee.SqliteDatabase(db_path)
    init_db(database)

    snapshot_input = os.path.join(output_path, "input_snapshot")

    score_workdir = os.path.join(output_path, f"_score_run_{fuzzer}_{program}")

    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
    os.makedirs(score_workdir, exist_ok=True)

    staged_names, alias_to_real = snapshot_dir_incremental(
        fuzzer=fuzzer,
        src_queue=seed_path,
        dst_dir=snapshot_input
    )

    if not staged_names:
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"No new non-sync seeds for {fuzzer}. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    args = gen_run_args(seed=snapshot_input, output=score_workdir, program=program)
    logger.info(f'Args : {args}')

    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        logger.info(f"Afl-fuzz failed (rc={result.returncode})")
        logger.info(f"Stdout: {result.stdout}")
        logger.info(f"Stderr: {result.stderr}")

    wait_for_file(path=score_path)

    if not os.path.exists(score_path):
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"Score file not created. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    alias_to_score = parse_score_file(score_path)

    name_to_score = {}
    for alias_seed_id, score_tuple in alias_to_score.items():
        real_seed_id = alias_to_real.get(alias_seed_id)

        if real_seed_id is None:
            logger.info(
                f"Score alias not found in alias_to_real: {alias_seed_id}, score={score_tuple}"
            )
            continue

        name_to_score[real_seed_id] = score_tuple

    logger.info(f"evaluator 224 - converted DAFL scores: {name_to_score}")

    name_to_dom_covered = evaluate_dom_covered_for_snapshot(
        snapshot_dir=snapshot_input,
        program=program,
        alias_to_real=alias_to_real
    )

    SeedModel = get_seed_model(fuzzer)
    with database.atomic():
        for name in staged_names:
            prox, bmsz = name_to_score.get(name, (None, None))
            dom_covered = name_to_dom_covered.get(name)

            row, _ = SeedModel.get_or_create(name=name)
            row.prox_score = prox
            row.bitmap_size = bmsz
            row.dom_covered = dom_covered
            row.save()

            logger.info(
                f"Save DB name={name}, "
                f"prox={prox}, bitmap={bmsz}, dom_covered={dom_covered}"
            )

    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)

    max_results = max_prox_from_db(fuzzer)
    logger.info(f"Fuzzer={fuzzer}, max_prox_score={max_results['max_prox_score']}, max_dom_covered={max_results['max_dom_covered']}")
    return max_results
