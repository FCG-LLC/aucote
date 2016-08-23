from unittest import TestCase

from tools.hydra.structs import HydraResults, HydraResult


class HydraResultTest(TestCase):
    def setUp(self):
        self.hydra_results = HydraResults()

    def test_add_none(self):
        self.assertEqual(len(self.hydra_results), 0)
        self.hydra_results.add('nothing')
        self.assertEqual(len(self.hydra_results), 0)
        self.hydra_results.add(HydraResult())
        self.assertEqual(len(self.hydra_results), 1)