from flask import Blueprint
from functools import partial
from api.utils import get_json, get_credentials, jsonify_result, jsonify_data
from api.schemas import ObservableSchema, ActionFormParamsSchema

respond_api = Blueprint('respond', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    _ = get_credentials()
    _ = get_observables()
    return jsonify_result()


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    _ = get_credentials()
    _ = get_action_form_params()
    return jsonify_data({'status': 'success'})
