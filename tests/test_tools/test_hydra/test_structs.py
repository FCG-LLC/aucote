from unittest import TestCase

from tools.hydra.structs import HydraResults, HydraResult


class HydraResultTest(TestCase):
    def setUp(self):
        self.hydra_results = HydraResults()

    def test_add_none(self):
        self.assertRaises(TypeError, self.hydra_results.add, None)

    def test_result_to_str(self):
        result = HydraResult(port='23', host='127.0.0.1', login='test_1', password='test_1', service='ssh')

        result = str(result)
        expected = "login: test_1\tpassword: test_1"

        self.assertEqual(result, expected)

    def test_results_to_str(self):
        result_1 = HydraResult(port='23', host='127.0.0.1', login='test_1', password='test_1', service='ssh')
        result_2 = HydraResult(port='23', host='127.0.0.1', login='test_2', password='test_2', service='ssh')

        self.hydra_results.add(result_1)
        self.hydra_results.add(result_2)

        result = str(self.hydra_results)
        expected = "\n".join([str(result_1), str(result_2)])

        self.assertEqual(result, expected)

        for result in self.hydra_results:
            self.assertIn(result, self.hydra_results._results)
