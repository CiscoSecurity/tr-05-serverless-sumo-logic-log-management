from datetime import datetime, timezone
from uuid import uuid5, NAMESPACE_X500

from flask import current_app
from urllib.parse import urlencode

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
        time = start_time + current_app.config['THIRTY_DAYS_IN_SECONDS']
        return time_format(time)
    return time_format(datetime(2525, 1, 1, tzinfo=timezone.utc))


def time_format(time):
    """
    Converts seconds or datetime object to needed format
    e.g. 2525-01-01T00:00:00.000+00:00
    """
    if not isinstance(time, datetime):
        time = datetime.fromtimestamp(time, timezone.utc)
    return f'{time.isoformat(timespec="milliseconds")}'


def source_uri():
    host = current_app.config['HOST']
    return f'https://{host.replace("api", "service")}/'


class Sighting:
    def _sighting(self, message, observable):
        sighting = {
            'count': self._count(message),
            'description': f'```\n{message.get("_raw")}\n```',
            'short_description': self._short_description(message),
            'external_ids': [
                message.get('_messageid')
            ],
            'id': f'transient:{SIGHTING}-{uuid5(NAMESPACE_X500, message.get("_messageid"))}',
            'observables': [observable],
            'observed_time': {
                'start_time': self._start_time(message)
            },
            'data': self._data_table(message),
            'source_uri': self.sighting_source_uri(
                f'_messageid = {message.get("_messageid")}',
                message.get('_messagetime'),
                int(message.get('_messagetime')) + 1
            ),
            **SIGHTING_DEFAULTS
        }

        if message.get('src_ip') and message.get('dest_ip'):
            sighting['relations'] = self._relation(message)

        return sighting

    @staticmethod
    def sighting_source_uri(query, start_time, end_time):
        url = source_uri()
        path = 'ui/#/search/create'
        params = {
            'query': query,
            'startTime': start_time,
            'endTime': end_time
        }
        return f'{url}{path}?{urlencode(params)}'

    @staticmethod
    def _start_time(message):
        message_timestamp = int(message.get('_messagetime')) / 10**3
        return time_format(message_timestamp)

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
                data['columns'].append({'name': key, 'type': 'string'})
                data['rows'][0].append(value)

        return data

    def extract(self, message, observable):
        sighting = self._sighting(message, observable)
        return sighting


class Judgement:
    def _judgement(self, cs_data, observable):
        judgement = {
            **DISPOSITION_MAP[cs_data['malicious_confidence']],
            'id': self._transient_id(cs_data, observable),
            'observable': observable,
            'severity': SEVERITY_MAP[cs_data['malicious_confidence']],
            'valid_time': {
                'start_time': time_format(cs_data['last_updated']),
                'end_time': valid_time(cs_data['last_updated'],
                                       observable['type'])
            },
            'external_references': self._external_references(cs_data),
            'source_uri': source_uri(),
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
        judgement_id = f'transient:{JUDGEMENT}-{uuid5(NAMESPACE_X500, seeds)}'
        return judgement_id

    def extract(self, crowd_strike_data, observable):
        judgement = self._judgement(crowd_strike_data, observable)
        return judgement


class Verdict:
    @staticmethod
    def _verdict(cs_data, observable):
        verdict = {
            **DISPOSITION_MAP[cs_data['malicious_confidence']],
            'observable': observable,
            'valid_time': {
                'start_time': time_format(cs_data['last_updated']),
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
