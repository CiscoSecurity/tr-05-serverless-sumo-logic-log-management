from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_X500

from flask import current_app

SIGHTING = 'sighting'
JUDGEMENT = 'judgement'
VERDICT = 'verdict'

SOURCE = 'Sumo Logic'
CONFIDENCE = 'High'
SCHEMA_VERSION = '1.1.6'

SIGHTING_DEFAULTS = {
    'confidence': CONFIDENCE,
    'schema_version': SCHEMA_VERSION,
    'source': SOURCE,
    'type': SIGHTING,
    'title': 'Log message from last 30 days in Sumo Logic contains '
             'observable',
    'internal': True
}
JUDGEMENT_DEFAULTS = {
    'confidence': CONFIDENCE,
    'schema_version': SCHEMA_VERSION,
    'source': SOURCE,
    'type': JUDGEMENT,
    'priority': 85,
    'reason': 'Found in CrowdStrike Intelligence',
    'reason_uri': 'https://www.crowdstrike.com/',
    'tlp': 'amber'
}
VERDICT_DEFAULTS = {
    'type': VERDICT
}

DISPOSITION_MAP = {
    'high': {
        'disposition': 2,
        'disposition_name': 'Malicious'
    },
    'medium': {
        'disposition': 2,
        'disposition_name': 'Malicious'
    },
    'low': {
        'disposition': 3,
        'disposition_name': 'Suspicious'
    },
    'unverified': {
        'disposition': 5,
        'disposition_name': 'Unknown'
    }
}

SEVERITY_MAP = {
    'high': 'High',
    'medium': 'Medium',
    'low': 'Low',
    'unverified': 'Unknown'
}


def valid_time(start_time, observable_type):
    if observable_type in ['domain', 'email', 'ip', 'ipv6', 'url']:
        return start_time + 30 * 24 * 60 * 60
    return datetime(2525, 1, 1)


class Sighting:
    def _sighting(self, message, observable):
        sighting = {
            'count': self._count(message),
            'description': f'```\n{message.get("_raw")}\n```',
            'short_description': self._short_description(message),
            'external_ids': [
                message.get('_messageid')
            ],
            'id': message.get('_messageid'),
            'observables': [observable],
            'observed_time': {
                'start_time': self._start_time(message)
            },
            'data': self._data_table(message),
            **SIGHTING_DEFAULTS
        }

        if message.get('src_ip') and message.get('dest_ip'):
            sighting['relations'] = self._relation(message)

        return sighting

    @staticmethod
    def _start_time(message):
        message_timestamp = int(message.get('_messagetime')) / 10 ** 3
        message_date = datetime.fromtimestamp(message_timestamp, timezone.utc)
        return message_date.isoformat(timespec='milliseconds')

    @staticmethod
    def _count(message):
        return (
            int(message.get('_messagecount')) if message.get('_messagecount')
            else 1)

    @staticmethod
    def _short_description(message):
        return f'{message.get("_collector")} received a log from ' \
               f'{message.get("_source")} - {message.get("_sourcename")} ' \
               'containing the observable'

    @staticmethod
    def _relation(message):
        return [{
            'origin': message.get('_source'),
            'relation': 'Connected_To',
            'source': {
                'type': 'ip',
                'value': message.get('src_ip')
            },
            'related': {
                'type': 'ip',
                'value': message.get('dest_ip')
            }
        }]

    @staticmethod
    def _data_table(message):
        data = {
            'columns': [],
            'rows': [[]]
        }

        for key, value in message.items():
            if not key.startswith('_') and value:
                data['columns'].append({"name": key, "type": "string"})
                data['rows'][0].append(value)

        return data

    def extract(self, message, observable):
        sighting = self._sighting(message, observable)
        return sighting


class Judgement():
    def _judgement(self, cs_data, observable):
        judgement = {
            **DISPOSITION_MAP[cs_data['malicious_confidence']],
            'id': self._transient_id(cs_data, observable),
            'observables': [observable],
            'severity': SEVERITY_MAP[cs_data['malicious_confidence']],
            'valid_time': {
                'start_time': cs_data['last_updated'],
                'end_time': valid_time(cs_data['last_updated'],
                                       observable['type'])
            },
            'external_references': self._external_references(cs_data),
            'source_uri': current_app.config['SUMO_API_ENDPOINT'],
            **JUDGEMENT_DEFAULTS,
        }
        return judgement

    @staticmethod
    def _external_references(cs_data):
        reports = cs_data['reports']
        references = []
        for report in reports:
            references.append({
                'source_name': 'CrowdStrike',
                'description': 'CrowdStrike Intelligence Report',
                'external_id': report
            })
        return references

    @staticmethod
    def _transient_id(cs_data, observable):
        disposition = DISPOSITION_MAP[cs_data['malicious_confidence']][
            "disposition"]
        seeds = f'{SOURCE}|{observable["value"]}|{disposition}|' \
                f'{cs_data["last_updated"]}'
        judgement_id = f'transient:judgement-{uuid5(NAMESPACE_X500, seeds)}'
        return judgement_id

    def extract(self, crowd_strike_data, observable):
        judgement = self._judgement(crowd_strike_data, observable)
        return judgement


class Verdict():
    def _verdict(self, cs_data, observable):
        verdict = {
            **DISPOSITION_MAP[cs_data['malicious_confidence']],
            'observables': [observable],
            'valid_time': {
                'start_time': cs_data['last_updated'],
                'end_time': valid_time(cs_data['last_updated'],
                                       observable['type'])
            },
            **VERDICT_DEFAULTS
        }
        return verdict

    def extract(self, crowd_strike_data, observable, judgement_id=None):
        verdict = self._verdict(crowd_strike_data, observable)
        if judgement_id:
            verdict['judgement_id'] = judgement_id
        return verdict
