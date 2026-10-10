"""Compare native batch wall time on identical offline firmware and patch inputs.

Uses direct file redirection, unique output paths, and alternating tool order.
Does not flush OS caches or access a handset. Requires enough disk for every run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--script', type=Path, required=True)
    parser.add_argument('--tool', action='append', required=True, help='name=executable')
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--output', type=Path, required=True, help='NEW benchmark directory')
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    tools = []
    for item in args.tool:
        name, sep, exe = item.partition('=')
        if not sep or not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name):
            parser.error('--tool must be a safe name=executable')
        path = Path(exe).resolve(strict=True)
        if not path.is_file() or name in [t[0] for t in tools]:
            parser.error('tool names must be unique and paths must be regular files')
        tools.append((name, path))
    source, script = args.input.resolve(strict=True), args.script.resolve(strict=True)
    report = dict(schemaVersion=1, platform=platform.platform(), input=str(source),
                  inputSHA256=digest(source), script=str(script), scriptSHA256=digest(script),
                  method='sequential alternating order; direct stdout/stderr to files; natural OS cache; native batch only',
                  tools={name:dict(executable=str(exe), sha256=digest(exe)) for name,exe in tools}, runs=[])
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    report_path = output / 'timings.json'
    for round_number in range(1, args.rounds + 1):
        order = tools if round_number % 2 else list(reversed(tools))
        for name, exe in order:
            target = output / ('%s-%d' % (name, round_number))
            command = [str(exe), 'batch', '-i', str(source), '-s', str(script), '-o', str(target)]
            print('Running %s round %d' % (name, round_number), flush=True)
            with (output / (target.name + '.log')).open('wb') as log:
                started = time.perf_counter()
                result = subprocess.run(command, cwd=script.parent, stdout=log, stderr=subprocess.STDOUT)
                elapsed = time.perf_counter() - started
            report['runs'].append(dict(tool=name, round=round_number, wallSeconds=elapsed,
                                       exitCode=result.returncode, output=str(target), command=command))
            report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            print('%s: %.3fs, exit %d' % (target.name, elapsed, result.returncode), flush=True)
            if result.returncode:
                raise SystemExit('Benchmark failed; inspect ' + str(output / (target.name + '.log')))
    if digest(source) != report['inputSHA256'] or digest(script) != report['scriptSHA256']:
        raise SystemExit('Benchmark inputs changed during comparison')
    report['inputsUnchanged'] = True
    report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(report_path)


if __name__ == '__main__':
    main()
