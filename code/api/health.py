from flask import Blueprint
from api.utils import get_credentials, jsonify_data
from api.client import Sighting

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    client = Sighting(credentials)
    _ = client.health()
    return jsonify_data({'status': 'ok'})
