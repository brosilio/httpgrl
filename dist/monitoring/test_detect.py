#!/usr/bin/env python3
"""Standard-library tests, including hostile log input and bounded correlation state."""
import io
import json
import random
import unittest
from detect import Detector, records, MAX_LINE

class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.policy = dict(window_seconds=300, max_keys=8, denials_before_success=3,
                           security_events=['routing_regex_timeout'],
                           resources=[dict(path_prefix='/.env', never_success=True),
                                      dict(path_prefix='/exports', max_response_bytes=100)])
        self.d = Detector(self.policy)
    def row(self, **kw):
        return dict(dict(ts='2026-11-08T00:00:00Z', event='http_access', instance='a',
                         remote='127.0.0.1', path='/private', host='test', status=403, bytes=0, outcome='complete'), **kw)
    def rules(self, **kw):
        return [a['rule'] for a in self.d.process(self.row(**kw))]
    def test_success_and_sensitive(self):
        for _ in range(3): self.rules()
        self.assertIn('denials_followed_by_success', self.rules(status=200))
        self.assertIn('unexpected_sensitive_success', self.rules(status=200, path='/.env'))
        self.assertNotIn('unexpected_sensitive_success', self.rules(status=200, path='/.environment'))
        self.assertIn('large_sensitive_response', self.rules(status=200, path='/exports', bytes=101))
        self.assertIn('successful_status_incomplete_response', self.rules(status=200, outcome='incomplete'))
    def test_expiry_host_and_peer_isolation(self):
        for _ in range(3): self.rules()
        self.assertNotIn('denials_followed_by_success', self.rules(status=200, host='other'))
        self.assertNotIn('denials_followed_by_success', self.rules(status=200, remote='other'))
        self.assertNotIn('denials_followed_by_success', self.rules(status=200, ts='2026-11-08T00:10:00Z'))
    def test_security_loss_and_audit(self):
        self.assertIn('routing_regex_timeout', self.rules(event='routing_regex_timeout'))
        self.assertIn('log_evidence_lost', self.rules(event='log_lines_dropped'))
        self.assertIn('log_record_truncated', self.rules(truncated=True))
        self.assertIn('application_authorization_violation', self.rules(event='application_audit', outcome='success', authorized=False))
    def test_bounded_records(self):
        self.assertEqual([None, b'{}\n'], list(records(io.BytesIO(b'x' * (MAX_LINE * 3) + b'\n{}\n'))))
        for i in range(1000): self.rules(path='/p/' + str(i))
        self.assertLessEqual(len(self.d.denied), 8)
    def test_invalid_policy(self):
        for bad in [dict(denials_before_success=0), dict(resources=[dict(path_prefix='relative')]),
                    dict(resources=[dict(path_prefix='/x', never_success='false')])]:
            with self.assertRaises(ValueError): Detector(bad)

    def test_mutated_input(self):
        rng = random.Random(83)
        values = [None, [], {}, 123, False, 'x', '2026-11-08T00:00:00Z', '\r\n']
        for _ in range(10000):
            r = self.row()
            r[rng.choice(list(r))] = rng.choice(values)
            try:
                for a in self.d.process(r): json.loads(json.dumps(a))
            except (ValueError, TypeError, KeyError, OverflowError, RecursionError): pass
            self.assertLessEqual(len(self.d.denied), 8)
            self.assertLessEqual(len(self.d.alerted), 8)

if __name__ == '__main__': unittest.main()
