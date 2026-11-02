import unittest

from scripts.select_iphone_simulator import select


class SelectIPhoneSimulatorTests(unittest.TestCase):
    def test_selects_current_iphone_when_old_model_missing(self):
        data = {'devices': {'com.apple.CoreSimulator.SimRuntime.iOS-26-0': [
            {'name': 'iPhone 17 Pro', 'udid': '11111111-1111-1111-1111-111111111111', 'isAvailable': True},
            {'name': 'iPad Pro', 'udid': '22222222-2222-2222-2222-222222222222', 'isAvailable': True}]}}
        self.assertEqual(select(data)[2:], ('iPhone 17 Pro', '11111111-1111-1111-1111-111111111111'))

    def test_prefers_newer_runtime_then_preferred_model(self):
        data = {'devices': {
            'com.apple.CoreSimulator.SimRuntime.iOS-18-5': [
                {'name': 'iPhone 16 Pro', 'udid': '11111111-1111-1111-1111-111111111111'}],
            'com.apple.CoreSimulator.SimRuntime.iOS-26-0': [
                {'name': 'iPhone 17', 'udid': '22222222-2222-2222-2222-222222222222'},
                {'name': 'iPhone 17 Pro', 'udid': '33333333-3333-3333-3333-333333333333'}]}}
        self.assertEqual(select(data)[2], 'iPhone 17 Pro')

    def test_refuses_unavailable_malformed_or_non_ios_devices(self):
        data = {'devices': {
            'com.apple.CoreSimulator.SimRuntime.iOS-26-0': [
                {'name': 'iPhone 17', 'udid': '11111111-1111-1111-1111-111111111111', 'isAvailable': False},
                {'name': 'iPhone 17 Pro', 'udid': 'invalid'}],
            'com.apple.CoreSimulator.SimRuntime.watchOS-26-0': [
                {'name': 'iPhone 17', 'udid': '22222222-2222-2222-2222-222222222222'}]}}
        with self.assertRaises(ValueError):
            select(data)


if __name__ == '__main__':
    unittest.main()
