from datetime import datetime, timezone


class Mapping:

    def __init__(self, observable):
        self.observable = observable

    @staticmethod
    def _short_description(message):
        return f'{message.get("_collector")} received a log from ' \
               f'{message.get("_source")} - {message.get("_sourcename")} ' \
               f'containing the observable'

    @staticmethod
    def _count(message):
        return (
            int(message.get('_messagecount')) if message.get('_messagecount')
            else 1)

    @staticmethod
    def _start_time(message):
        message_timestamp = int(message.get('_messagetime')) / 10**3
        message_date = datetime.fromtimestamp(message_timestamp, timezone.utc)
        return message_date.isoformat(timespec='milliseconds')

    def _sighting(self, message, data_table):
        sighting = {
            'confidence': 'High',
            'count': self._count(message),
            'title': 'Log message from last 30 days '
                     'in Sumo Logic contains observable',
            'description': f'```\n{message.get("_raw")}\n```',
            'internal': True,
            'short_description': self._short_description(message),
            'external_ids': [
                message.get('_messageid')
            ],
            'id': message.get('_messageid'),
            'observables': [self.observable],
            'observed_time': {
                'start_time': self._start_time(message)
            },
            'schema_version': '1.1.5',
            'source': 'Sumo Logic',
            'type': 'sighting',
            'data': data_table
        }

        if message.get('src_ip') and message.get('dest_ip'):
            sighting['relations'] = self._relation(message)

        return sighting

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

    def extract_sighting(self, message):
        data_table = self._data_table(message)
        sighting = self._sighting(message, data_table)
        return sighting
