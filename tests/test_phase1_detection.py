"""Phase 1 detection contracts. All input is generated synthetic text."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shared import pii_engine as engine


def scan_names(content):
    return {f['pattern_name'] for f in engine.scan_content(content)}


class MetadataBoundaryTests(unittest.TestCase):
    def test_supported_underscore_labels(self):
        cases = {
            'IEP_504_FLAG': ['iep_status', 'accommodation_plan_id', 'individualized_education_program'],
            'DISCIPLINE_RECORD': ['suspension_count', 'oss_days'],
            'MEDICAL_INFO': ['medication_notes', 'allergy_list', 'seizure_plan', 'diagnosis_code'],
        }
        for pattern, labels in cases.items():
            for label in labels:
                with self.subTest(pattern=pattern, label=label):
                    self.assertIn(pattern, scan_names('student\n' + label))

    def test_lookalikes_and_unicode_letters_are_not_boundaries(self):
        for label in ['sleep_status', 'recipe_status', 'sniped_status', 'biep_status', 'éiep_status', 'iepé_status']:
            with self.subTest(label=label):
                self.assertNotIn('IEP_504_FLAG', scan_names('student\n'+label))

    def test_context_gates_remain_required(self):
        self.assertFalse(scan_names('iep_status,medication_notes,suspension_count'))

    def test_prose_and_case_still_match(self):
        self.assertIn('IEP_504_FLAG', scan_names('Student IEP accommodation plan'))
        self.assertIn('MEDICAL_INFO', scan_names('student MEDICATION_NOTES'))

    def test_shared_separator_does_not_consume_next_match(self):
        findings = engine.scan_content('student\niep_iep_iep')
        self.assertEqual(next(f['count'] for f in findings if f['pattern_name']=='IEP_504_FLAG'), 3)

    def test_metadata_only_caps_at_warn(self):
        findings = engine.scan_content('student\niep_status medication_notes suspension_count')
        self.assertEqual(engine.worst_action(findings), 'warn')
        self.assertTrue(all(f['is_metadata'] for f in findings))

    def test_value_lifts_metadata_cap(self):
        findings = engine.scan_content('student\niep_status medication_notes suspension_count\nsynthetic@example.invalid')
        self.assertEqual(engine.worst_action(findings), 'block')

    def test_non_target_patterns_not_expanded(self):
        self.assertNotIn('PARENT_GUARDIAN',scan_names('student_parent_email_address'))
        self.assertNotIn('SASID',scan_names('student_sasid='+'0'*10))
        self.assertNotIn('STUDENT_ID_LABELED',scan_names('prefix_student_id='+'0'*7))
        self.assertNotIn('LUNCH_PIN',scan_names('student_lunch_pin='+'0'*4))

    def test_previous_cache_cannot_hide_metadata(self):
        with tempfile.TemporaryDirectory(prefix='phase1-cache-') as temporary:
            home = Path(temporary)
            target = home/'schema.csv'
            target.write_text('student,iep_status,medication_notes,suspension_count\n')
            stat = target.stat()
            cache = home/'.claude/ferpa-guard-cache.json'
            cache.parent.mkdir()
            cache.write_text(json.dumps({'version':4,'entries':[{'key':[str(target),stat.st_mtime,stat.st_size], 'findings':[], 'cached_at':time.time()}]}))
            env={k:v for k,v in os.environ.items() if not k.startswith(('FERPA_GUARD_','PII_GUARDIAN_'))}
            env.update(HOME=temporary, FERPA_GUARD_CACHE='1')
            proc=subprocess.run([sys.executable,str(ROOT/'claude-code/pii_guardian.py')], input=json.dumps({'tool_name':'Read','tool_input':{'file_path':str(target)}}), env=env,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0)
            self.assertIn('Possible sensitive data',proc.stderr)
            self.assertGreater(json.loads(cache.read_text())['version'],4)


class MetadataVocabularyTests(unittest.TestCase):
    def test_504_and_sped_schema_vocabulary(self):
        for label in ['section_504', '504_flag', 'student_504', 'sped_status', 'SPED', '504 plan']:
            with self.subTest(label=label):
                self.assertIn('IEP_504_FLAG', scan_names('student\n'+label))

    def test_longer_numbers_and_words_do_not_match(self):
        for label in ['15040', '5040', 'spedition', 'unsped']:
            with self.subTest(label=label):
                self.assertNotIn('IEP_504_FLAG', scan_names('student\n'+label))

    def test_noneducation_status_and_verb_remain_silent(self):
        self.assertNotIn('IEP_504_FLAG', scan_names('HTTP status 504; sped up the build'))

    def test_education_prose_ambiguity_is_metadata(self):
        fs=engine.scan_content('student sped to room 504')
        self.assertIn('IEP_504_FLAG',{f['pattern_name'] for f in fs})
        self.assertTrue(all(f['is_metadata'] for f in fs))
        self.assertEqual(engine.worst_action(fs),'warn')

    def test_ambiguous_metadata_with_value_can_block(self):
        fs=engine.scan_content('student sped to room 504; synthetic@example.invalid')
        self.assertEqual(engine.worst_action(fs),'block')


if __name__ == '__main__':
    unittest.main()
