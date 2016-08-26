from unittest import TestCase

from tools.hydra.structs import HydraResults, HydraResult


class HydraResultTest(TestCase):
    def setUp(self):
        self.hydra_results = HydraResults()

    def test_add_none(self):
        self.assertRaises(TypeError, self.hydra_results.add, None)

    def test_result_str(self):
        result_1 = HydraResult(port='23', host='127.0.0.1', login='test_1', password='test_1', service='ssh')
        self.assertEqual(str(result_1), "login: test_1\tpassword: test_1")

    def test_results_str(self):
        result_1 = HydraResult(port='23', host='127.0.0.1', login='test_1', password='test_1', service='ssh')
        result_2 = HydraResult(port='23', host='127.0.0.1', login='test_2', password='test_2', service='ssh')

        self.hydra_results.add(result_1)
        self.hydra_results.add(result_2)

        self.assertEqual(str(self.hydra_results), "\n".join([str(result_1), str(result_2)]))

        for result in self.hydra_results:
            self.assertIn(result, self.hydra_results._results)
