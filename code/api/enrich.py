from functools import partial

from flask import Blueprint, g, current_app

from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_result, jsonify_data
from api.mapping import Sighting, Judgement, Verdict
from api.client import SumoLogicClient

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []
    g.judgements = []
    g.verdicts = []

    sighting_map = Sighting()
    judgment_map = Judgement()
    verdict_map = Verdict()

    client = SumoLogicClient(credentials)

    for observable in observables:
        messages = client.get_messages(observable['value'])

        for message in messages:
            sighting = sighting_map.extract(message['map'], observable)
            g.sightings.append(sighting)

        crowd_strike_data = client.get_crowd_strike_data(
            observable['value'])
        if crowd_strike_data:
            judgment = judgment_map.extract(crowd_strike_data, observable)
            g.judgements.append(judgment)
            verdict = verdict_map.extract(crowd_strike_data, observable,
                                          judgment['id'])
            g.verdicts.append(verdict)

    return jsonify_result()


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.verdicts = []

    verdict_map = Verdict()

    client = SumoLogicClient(credentials)

    for observable in observables:
        crowd_strike_data = client.get_crowd_strike_data(
            observable['value'])
        if crowd_strike_data:
            verdict = verdict_map.extract(crowd_strike_data, observable)
            g.verdicts.append(verdict)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_credentials()
    observables = get_observables()

    obs_types_map = current_app.config['HUMAN_READABLE_OBSERVABLE_TYPES']
    relay_output = [
        {
            'id': (
                f'ref-sumo-search-{observable["type"].replace("_", "-")}'
                f'-{observable["value"]}'
            ),
            'title': (
                f'Search for this {obs_types_map.get(observable["type"])}'
            ),
            'description': (
                f'Search for this {obs_types_map.get(observable["type"])}'
                ' in the Sumo Logic console'
            ),
            'url': Sighting.sighting_source_uri(f'"{observable["value"]}"',
                                                '-30d',
                                                'now'),
            'categories': ['Search', 'SumoLogic']
        }
        for observable in observables
    ]
    return jsonify_data(relay_output)
