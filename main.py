from werkzeug.debug import DebuggedApplication
from flask import Flask

# Import the views we want
from views.Root import RootView

pastebin = Flask(__name__)
pastebin.wsgi_app = DebuggedApplication(pastebin.wsgi_app, evalex=True)
pastebin.config['PROPOGRATE_EXCEPTIONS'] = True
pastebin.debug = True
pastebin.secret_key = 'RaNd0m-EnCrYpTiOn-KeY'

# Register the views with Flask
RootView.register(pastebin)

if __name__ == '__main__':
	pastebin.run(debug=True)
