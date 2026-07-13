import unittest

from apps.reconnaissance.inspectors import PublicIntelligenceInspector


class PublicIntelligenceInspectorTests(unittest.TestCase):
    def test_detects_email_provider_from_mx_records(self):
        inspector = PublicIntelligenceInspector(timeout=1)

        provider = inspector._detect_email_provider([
            {'value': 'aspmx.l.google.com'},
            {'value': 'alt1.aspmx.l.google.com'},
        ])

        self.assertEqual(provider, 'google_workspace')

    def test_detects_microsoft_365_provider_from_mx_records(self):
        inspector = PublicIntelligenceInspector(timeout=1)

        provider = inspector._detect_email_provider([
            {'value': 'mail.protection.outlook.com'},
        ])

        self.assertEqual(provider, 'microsoft_365')

    def test_extracts_subdomains_from_certificate_entries(self):
        inspector = PublicIntelligenceInspector(timeout=1)

        entries = [
            {'name_value': 'api.example.com\nwww.example.com'},
            {'common_name': '*.example.com'},
            {'name_value': 'mail.example.com\napi.example.com'},
        ]

        subdomains = inspector._extract_certificate_subdomains(entries)

        self.assertEqual(subdomains, ['api.example.com', 'mail.example.com', 'www.example.com'])
