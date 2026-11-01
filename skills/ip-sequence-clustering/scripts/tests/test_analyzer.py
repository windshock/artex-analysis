import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from analyze_ip_sequences import jaccard,kendall_tau,analyze,parse_manual

class AnalyzerTests(unittest.TestCase):
    def test_jaccard(self):
        self.assertAlmostEqual(jaccard(["a","b"],["b","c"]),1/3)
    def test_kendall_identical(self):
        self.assertEqual(kendall_tau(["a","b","c"],["a","b","c"]),1)
    def test_kendall_reverse(self):
        self.assertEqual(kendall_tau(["a","b","c"],["c","b","a"]),-1)
    def test_single_shared_undefined(self):
        self.assertIsNone(kendall_tau(["a"],["a"]))
    def test_manual_bounds(self):
        self.assertEqual(parse_manual("1-3,4-6",6),[(0,3),(3,6)])
    def test_phase_validation(self):
        a=["10.0.0.1","10.0.0.2","10.0.0.3"]*3
        b=["10.0.1.1","10.0.1.2","10.0.1.3"]*3
        result=analyze(a+b,[(0,len(a)),(len(a),len(a+b))])
        self.assertEqual(len(result["phases"]),2)
        self.assertTrue(all(p["validated"] for p in result["phases"]))
    def test_cross_phase(self):
        a=["10.0.0.1","10.0.0.2","10.0.0.3"]*3
        b=["10.0.0.1","10.0.1.2","10.0.1.3"]*3
        out=analyze(a+b,[(0,9),(9,18)])
        self.assertIn("10.0.0.1",[x["ip"] for x in out["anomalies"] if x["reason"]=="CROSS_PHASE"])
    def test_no_false_cycle_on_unique_sequence(self):
        ips=[f"10.0.0.{i}" for i in range(1,19)]
        out=analyze(ips)
        self.assertFalse(any(p["validated"] for p in out["phases"]))
if __name__=="__main__":unittest.main()
