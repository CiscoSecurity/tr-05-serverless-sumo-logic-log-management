from functools import partial

from flask import Blueprint, g

from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_result
from api.mapping import Mapping
from api.client import Sighting, JudgementVerdict

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []
    g.judgements = []

    sighting_client = Sighting(credentials)
    judgment_client = JudgementVerdict(credentials)

    for observable in observables:
        mapping = Mapping(observable)
        messages = sighting_client.get_data(observable['value'])

        for message in messages:
            sighting = mapping.extract_sighting(message['map'])
            g.sightings.append(sighting)

        judgment_messages = judgment_client.get_data(observable['value'])
        judgment_message = judgment_messages[0]['map'] if judgment_messages else {}
        if judgment_message.get('raw'):
            judgment = mapping.extract_judgement(judgment_message['raw'])
            g.judgements.append(judgment)

    return jsonify_result()
