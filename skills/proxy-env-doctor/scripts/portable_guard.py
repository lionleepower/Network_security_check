"""Public v2 guard CLI. Uses the bundled adapter; never launches a browser/Claude."""
import argparse
import json
from pathlib import Path
import subprocess
from guard_config import validate
from guard_store import lock
from ippure_guard import Guard
import browser_pause_latch


class PortableAdapter:
    def __init__(self, config, directory):
        self.config, self.directory = config, Path(directory)

    def route(self, action, **data):
        command = [self.config['node_runtime'], str(Path(__file__).with_name('mihomo_guard_adapter.cjs')),
                   str(self.directory / 'config.json'), action]
        result = subprocess.run(command, input=json.dumps(data), encoding='utf-8', capture_output=True,
                                timeout=180, check=True)
        return json.loads(result.stdout)

    def pause(self, journal):
        browser = self.config['browser']
        return browser_pause_latch.pause(Path(browser['profile']), journal, scope=browser)

    def resume(self, journal):
        return browser_pause_latch.resume(journal)


class PortableGuard(Guard):
    def __init__(self, directory, adapter=None, check_files=True):
        super().__init__(directory, adapter=adapter)
        source = validate(self.config, check_files=check_files)
        self.adapter = adapter or PortableAdapter(source, directory)
        self.config = {**source, 'extension_instance': source['browser']['extension_instance'],
                       'approved_nodes': source['routing']['nodes']}

    def ingest(self, raw):
        try:
            return super().ingest(raw)
        except (subprocess.SubprocessError, OSError, ValueError):
            # An unobserved transport error is not a leak. Keep incident state.
            if self.state.get('phase') in ('switch_required', 'suspend_required'):
                return self.halt('interrupted_operation')
            self.state['action'] = 'detector_channel_unavailable'
            self.write()
            return self.summary()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('command', choices=['validate', 'status', 'ingest', 'recover', 'resume', 'enable', 'disable'])
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve(strict=True)
    config = json.loads((directory / 'config.json').read_text(encoding='utf-8'))
    if args.command == 'validate':
        validate(config, check_files=True)
        print(json.dumps({'valid': True, 'network_accessed': False})); return
    with lock(directory / 'guard.lock'):
        guard = PortableGuard(directory)
        if args.command == 'ingest':
            if not args.input or args.input.stat().st_size > 65536:
                raise ValueError('bounded_observation_file_required')
            result = guard.ingest(json.loads(args.input.read_text(encoding='utf-8')))
        elif args.command == 'disable':
            guard.state['enabled'] = False; guard.write(); result = guard.summary()
        else:
            result = getattr(guard, {'status':'summary', 'resume':'manual_resume'}.get(args.command, args.command))()
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'error':'portable_guard_failed', 'instruction':'Check private configuration and state. Never auto-resume or repeat a switch.'}))
        raise SystemExit(1)
