#!/usr/bin/env python3
"""Bounded offline/streaming detector for httpgrl JSON lines. No network or runtime dependency in httpgrl."""
import argparse
from collections import OrderedDict
from datetime import datetime
import json
import sys

MAX_LINE = 65536

class Detector:
    def __init__(self, policy):
        self.policy = policy
        self.window = int(policy.get('window_seconds', 300))
        self.limit = int(policy.get('max_keys', 10000))
        if not 1 <= self.window <= 86400 or not 1 <= self.limit <= 100000:
            raise ValueError('invalid detector bounds')
        threshold = policy.get('denials_before_success', 3)
        if type(threshold) is not int or threshold < 1:
            raise ValueError('denials_before_success must be positive')
        events = policy.get('security_events', [])
        if not isinstance(events, list) or not all(isinstance(e, str) for e in events):
            raise ValueError('security_events must be strings')
        resources = policy.get('resources', [])
        if not isinstance(resources, list):
            raise ValueError('resources must be a list')
        for rule in resources:
            if not isinstance(rule, dict) or not isinstance(rule.get('path_prefix'), str) or not rule['path_prefix'].startswith('/'):
                raise ValueError('resource needs an absolute path_prefix')
            if 'host' in rule and not isinstance(rule['host'], str):
                raise ValueError('resource host must be a string')
            if 'never_success' in rule and type(rule['never_success']) is not bool:
                raise ValueError('never_success must be boolean')
            if 'max_response_bytes' in rule and (type(rule['max_response_bytes']) is not int or rule['max_response_bytes'] < 0):
                raise ValueError('max_response_bytes must be nonnegative')
        self.denied = OrderedDict()
        self.alerted = OrderedDict()
        self.watermark = 0.0
        self.eviction_reported = False

    def process(self, r):
        if not isinstance(r, dict):
            raise ValueError('record must be an object')
        stamp = r.get('ts')
        if not isinstance(stamp, str) or len(stamp) > 40:
            raise ValueError('missing timestamp')
        dt = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('timestamp must have timezone')
        now = dt.timestamp()
        self.watermark = max(now, self.watermark)
        for state in (self.denied, self.alerted):
            while state and next(iter(state.values()))[0] < self.watermark - self.window:
                state.popitem(last=False)
        # Correlation expects chronological input; old records still get stateless checks.
        timely = now >= self.watermark - self.window
        out = []
        def alert(rule, severity='warning'):
            key = (rule, r.get('instance', ''), r.get('remote', ''), r.get('host', ''), r.get('path', ''))
            if any(not isinstance(x, str) for x in key):
                raise ValueError('invalid correlation field')
            if timely and key in self.alerted:
                return
            if timely:
                self.alerted[key] = (self.watermark, 1)
                if len(self.alerted) > self.limit:
                    self.alerted.popitem(last=False)
            out.append(dict(event='security_alert', rule=rule, severity=severity,
                            ts=stamp, evidence={k: r[k] for k in
                            ('instance', 'process_id', 'request_id', 'conn', 'remote', 'path', 'status', 'outcome') if k in r}))
        event = r.get('event', '')
        if not isinstance(event, str):
            raise ValueError('invalid event')
        if event == 'log_lines_dropped':
            alert('log_evidence_lost', 'critical')
        if r.get('truncated') is True:
            alert('log_record_truncated')
        if event in self.policy.get('security_events', []):
            alert(event)
        if event == 'application_audit' and r.get('outcome') == 'success' and r.get('authorized') is False:
            alert('application_authorization_violation', 'critical')
        if event != 'http_access':
            return out
        path, remote, host = r.get('path', ''), r.get('remote', ''), r.get('host', '')
        if not all(isinstance(v, str) for v in (path, remote, host)):
            raise ValueError('invalid request fields')
        status, size = r.get('status'), r.get('bytes')
        if type(status) is not int or type(size) is not int or size < 0:
            raise ValueError('invalid status or byte count')
        key = (r.get('instance', ''), remote, host, path)
        if not isinstance(key[0], str):
            raise ValueError('invalid instance')
        if status in (401, 403, 404, 429) and timely:
            previous = self.denied.get(key, (self.watermark, 0))
            self.denied[key] = (previous[0], previous[1] + 1)
            if len(self.denied) > self.limit:
                self.denied.popitem(last=False)
        success = 200 <= status < 300
        if success and timely and self.denied.get(key, (0, 0))[1] >= self.policy.get('denials_before_success', 3):
            alert('denials_followed_by_success')
        if success and r.get('outcome') != 'complete':
            alert('successful_status_incomplete_response')
        for rule in self.policy.get('resources', []):
            if rule.get('host') and host != rule['host']:
                continue
            prefix = rule['path_prefix']
            if path != prefix and not path.startswith(prefix.rstrip('/') + '/'):
                continue
            if success and rule.get('never_success', False):
                alert('unexpected_sensitive_success', 'critical')
            if success and size > rule.get('max_response_bytes', 2**63):
                alert('large_sensitive_response')
        if len(self.denied) >= self.limit and not self.eviction_reported:
            self.eviction_reported = True
            out.append(dict(event='security_alert', rule='correlation_capacity_reached', ts=stamp,
                            severity='warning', detail='State is bounded; correlation may be incomplete. Increase max_keys or partition by instance.'))
        return out

def records(stream):
    while True:
        line = stream.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE:
            while line and not line.endswith(b'\n'):
                line = stream.readline(MAX_LINE + 1)
            yield None
        else:
            yield line

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--policy', required=True)
    args = ap.parse_args()
    with open(args.policy, encoding='utf-8') as f:
        detector = Detector(json.load(f))
    invalid = 0
    for line in records(sys.stdin.buffer):
        try:
            if line is None:
                raise ValueError('oversized line')
            alerts = detector.process(json.loads(line))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            invalid += 1
            # Report loss promptly, but don't turn malformed input into an alert flood.
            if invalid & (invalid - 1) == 0:
                print(json.dumps(dict(event='security_alert', rule='invalid_log_input', severity='warning', invalid_records=invalid)), flush=True)
            continue
        for alert in alerts:
            print(json.dumps(alert, ensure_ascii=True), flush=True)
    if invalid:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
