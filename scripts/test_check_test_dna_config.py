"""Offline stdlib configuration checks. These do not execute Holochain."""
import base64
import unittest
from check_test_dna_config import ConfigError, check, location

def fixture(keys=5):
    rt=[base64.b64encode(bytes([i])*32).decode() for i in (1,2)]
    agents=[]
    for i in (3,4,5)[:max(0,keys-2)]:
        key=bytes([i])*32
        value=bytes([0x84,0x20,0x24])+key+location(key)
        agents.append("u"+base64.urlsafe_b64encode(value).decode().rstrip("="))
    return "\n".join(["    max_faulty: 1","    min_sources: 3",
        "    roughtime_servers:",*(f'      - "{v}"' for v in rt),
        "    oracles:",*(f'      - "{v}"' for v in agents)])

class PreflightTests(unittest.TestCase):
    def test_quorum_syntax_is_not_operator_validation(self):
        r=check(fixture())
        self.assertEqual(r["min_sources"],3)
        self.assertFalse(r["operator_independence_proven"])
        self.assertFalse(r["bundle_manifest_match_proven"])
    def test_placeholders_are_blocked(self):
        with self.assertRaisesRegex(ConfigError,"placeholder"):check(fixture()+"\nREPLACE_WITH")
    def test_not_enough_sources(self):
        with self.assertRaisesRegex(ConfigError,"insufficient"):check(fixture(3))
    def test_duplicate_source(self):
        s=fixture();lines=s.splitlines();lines[4]=lines[3]
        with self.assertRaisesRegex(ConfigError,"duplicate"):check("\n".join(lines))
    def test_bad_agent_checksum(self):
        s=fixture().replace("uhCAk","uhC0k")
        with self.assertRaises(ConfigError):check(s)
    def test_unsound_fault_quorum(self):
        with self.assertRaisesRegex(ConfigError,"fault quorum"):check(fixture().replace("min_sources: 3","min_sources: 1"))

if __name__=="__main__":unittest.main()
