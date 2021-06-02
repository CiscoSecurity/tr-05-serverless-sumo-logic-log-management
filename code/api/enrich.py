from flask import Blueprint, g
from functools import partial
from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_result
from api.mapping import Mapping
from api.client import SumoLogicClient

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_credentials()
    _ = get_observables()
    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []

    client = SumoLogicClient(credentials)

    for observable in observables:
        mapping = Mapping(observable)
        messages = client.get_data(observable['value'])

        for message in messages:
            sighting = mapping.extract_sighting(message['map'])
            g.sightings.append(sighting)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_credentials()
    _ = get_observables()
    return jsonify_result()
