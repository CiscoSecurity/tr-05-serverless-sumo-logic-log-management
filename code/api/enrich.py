from functools import partial

from flask import Blueprint, g

from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_result
from api.mapping import Mapping
from api.client import SumoLogicClient

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []
    g.judgements = []

    client = SumoLogicClient(credentials)

    for observable in observables:
        mapping = Mapping(observable)
        messages = client.get_messages(observable['value'])

        for message in messages:
            sighting = mapping.extract_sighting(message['map'])
            g.sightings.append(sighting)

        crowd_strike_data = client.get_crowd_strike_data(
            observable['value'])
        if crowd_strike_data:
            judgment = mapping.extract_judgement(crowd_strike_data)
            g.judgements.append(judgment)

    return jsonify_result()
