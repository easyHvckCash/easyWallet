#!/usr/bin/env python3
"""
POC Unified Runner - handles CLI, batch output, and rate limiting.
Each POC only needs to implement the PocGenerator interface, driven by this Runner.
Outputs structured info via stdout for Rust to parse and write to SQLite.

Protocol:
  ##PROGRESS## {"index":N,"batch_num":N,"total_generated":N,"total_space":N}
  ##LOG## arbitrary log text

Usage:
  py -3 main.py --poc dice_no_floor --output ./files/waittocheck/dice_no_floor --maxfile 200 --start-index 0 --start-batch 0
"""
import sys, os, time, signal, argparse, tempfile, uuid, importlib, importlib.util, json

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_shutdown_requested = False


def _handle_sigterm(signum, frame):
    global _shutdown_requested
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_sigterm)
signal.signal(signal.SIGINT, _handle_sigterm)


# === Output Protocol ===

def emit_progress(index: int, batch_num: int, total_generated: int, total_space: int):
    data = json.dumps({"index": index, "batch_num": batch_num,
                       "total_generated": total_generated, "total_space": total_space})
    print(f"##PROGRESS## {data}", flush=True)


def emit_log(msg: str):
    print(f"##LOG## {msg}", flush=True)


# === File IO ===

def atomic_write_file(filepath: str, content: str):
    dir_path = os.path.dirname(filepath)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path or '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filepath)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def unique_batch_filename(output_dir: str, poc_id: str, batch_num: int) -> str:
    short_id = uuid.uuid4().hex[:8]
    return os.path.join(output_dir, f"{poc_id}_batch_{batch_num:06d}_{short_id}.txt")


def count_files(directory: str) -> int:
    try:
        return len([f for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f))])
    except FileNotFoundError:
        return 0


def wait_until_below_limit(output_dir: str, maxfile: int) -> int:
    while not _shutdown_requested:
        n = count_files(output_dir)
        if n < maxfile:
            return n
        emit_log(f"  [Wait] dir file count={n} >=limit, pausing generation, rechecking in 60s...")
        for _ in range(60):
            if _shutdown_requested:
                return n
            time.sleep(1)
    return 0


# === Generator Registry ===

def discover_generators() -> dict:
    generators = {}
    targets_dir = os.path.join(HERE, "targets")

    for vendor in _safe_listdir(targets_dir):
        vendor_path = os.path.join(targets_dir, vendor)
        if not os.path.isdir(vendor_path) or vendor.startswith('_'):
            continue
        for poc_dir in _safe_listdir(vendor_path):
            poc_path = os.path.join(vendor_path, poc_dir)
            gen_file = os.path.join(poc_path, "generator.py")
            if not os.path.isfile(gen_file):
                continue
            try:
                module_name = f"targets.{vendor}.{poc_dir}.generator"
                spec = importlib.util.spec_from_file_location(module_name, gen_file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if not isinstance(attr, type):
                        continue
                    if attr_name == 'PocGenerator':
                        continue
                    # Duck-type check: must have poc_id, poc_name, total_space, generate
                    if (hasattr(attr, 'poc_id') and hasattr(attr, 'poc_name')
                            and hasattr(attr, 'total_space') and hasattr(attr, 'generate')):
                        try:
                            inst = attr()
                            pid = inst.poc_id
                            if pid:
                                generators[pid] = inst
                        except (TypeError, NotImplementedError):
                            pass
            except Exception as e:
                emit_log(f"  [Warn] Failed to load {gen_file} :  {e}")

    return generators


def _safe_listdir(path: str) -> list:
    try:
        return [d for d in os.listdir(path) if not d.startswith('.')]
    except FileNotFoundError:
        return []


# === Main Runner ===

def run_poc(generator, output_dir: str, maxfile: int, start_index: int, start_batch: int):
    global _shutdown_requested
    poc_id = generator.poc_id

    os.makedirs(output_dir, exist_ok=True)

    batch_num = start_batch
    total_done = start_index

    emit_log(f"POC Runner: {generator.poc_name}")
    emit_log(f"  POC ID:       {poc_id}")
    emit_log(f"  Output dir:         {output_dir}")
    emit_log(f"  Max dir files:  {maxfile}")
    emit_log(f"  Total space:      {generator.total_space:,}")
    emit_log(f"  Batch size:       {generator.batch_size:,}")
    if start_index > 0:
        emit_log(f"  Resuming:           index={start_index:,}, done={total_done:,}")

    batch_buffer = []
    t_start = time.time()
    last_report = t_start

    try:
        for (idx, mnemonic) in generator.generate(start_index):
            if _shutdown_requested:
                emit_log("  [Signal] Shutdown requested, saving progress...")
                break

            if mnemonic is not None:
                batch_buffer.append(mnemonic)
            total_done = idx + 1

            if len(batch_buffer) >= generator.batch_size:
                wait_until_below_limit(output_dir, maxfile)
                if _shutdown_requested:
                    break

                batch_file = unique_batch_filename(output_dir, poc_id, batch_num)
                atomic_write_file(batch_file, '\n'.join(batch_buffer) + '\n')
                batch_buffer = []
                batch_num += 1
                emit_progress(total_done, batch_num, total_done, generator.total_space)

                now = time.time()
                if now - last_report >= 5.0:
                    elapsed = now - t_start
                    speed = (total_done - start_index) / elapsed if elapsed > 0 else 0
                    pct = total_done / generator.total_space * 100
                    emit_log(f"  [{pct:7.4f}%] {total_done:>12,} / {generator.total_space:,} "
                             f"| {speed:.0f}/s")
                    last_report = now

        if batch_buffer:
            wait_until_below_limit(output_dir, maxfile)
            batch_file = unique_batch_filename(output_dir, poc_id, batch_num)
            atomic_write_file(batch_file, '\n'.join(batch_buffer) + '\n')
            batch_num += 1

        emit_progress(total_done, batch_num, total_done, generator.total_space)

        elapsed = time.time() - t_start
        if _shutdown_requested:
            emit_log(f"  Paused! Progress saved: index={total_done:,}, will resume next run")
        elif total_done >= generator.total_space:
            emit_log(f"  Done! {total_done - start_index:,} items, "
                     f"elapsed {elapsed:.1f}s, files {batch_num}")
        else:
            emit_log(f"  Run ended: {total_done:,} / {generator.total_space:,}")

    except Exception as e:
        if batch_buffer:
            batch_file = unique_batch_filename(output_dir, poc_id, batch_num)
            atomic_write_file(batch_file, '\n'.join(batch_buffer) + '\n')
            batch_num += 1
        emit_progress(total_done, batch_num, total_done, generator.total_space)
        emit_log(f"  [Error] {e}")
        raise


def main():
    parser = argparse.ArgumentParser(description="POC Unified Runner")
    parser.add_argument("--poc", type=str, required=True)
    parser.add_argument("--output", "-o", type=str)
    parser.add_argument("--maxfile", type=int, default=200)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--start-batch", type=int, default=0)
    args = parser.parse_args()

    generators = discover_generators()

    if args.poc == "list":
        for poc_id, gen in sorted(generators.items()):
            print(f"  {poc_id:24s} {gen.poc_name} (space: {gen.total_space:,})")
        return

    if args.poc not in generators:
        emit_log(f"Error: unknown POC '{args.poc}'")
        sys.exit(1)

    if not args.output:
        emit_log("Error: --output argument required")
        sys.exit(1)

    generator = generators[args.poc]
    run_poc(generator, args.output, args.maxfile, args.start_index, args.start_batch)


if __name__ == "__main__":
    main()
