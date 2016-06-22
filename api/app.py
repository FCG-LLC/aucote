from flask import Flask
import logging as log

#create the global instance of Flask here
app = Flask(__name__)
#to avoid cyclic dependency import needs to be after app
import api.views

def run(cfg):
    '''
    Starts the API.

    Args:
        cfg(Config) - configuration of the application
    '''
    log.info('Running API')
    app.run(debug=False, host=cfg.get('service.api.v1.host'), port=cfg.get('service.api.v1.port'))