import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    SIGHTING = {
        'search_query': '"{}" | limit 101',
        'search_time_range': 30 * 24 * 60 * 60 * 10**3,  # 30 days in milliseconds
        'check_request_delay': 3,
        'first_check_request_delay': 0
    }
    JUDGMENT_VERDICT = {
        'search_query': '| limit 1 | "{}" as observable | lookup raw from sumo://threat/cs on threat=observable',
        'search_time_range': 15 * 60 * 10**3,  # 15 minutes in milliseconds
        'check_request_delay': 5,
        'first_check_request_delay': 1
    }
