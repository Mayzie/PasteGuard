from flask import render_template

from flask.ext.classy import FlaskView

class RootView(FlaskView):
    route_base = '/'

    def index(self):
        return render_template('index.html', trim_blocks = True, lstrip_blocks = True)
