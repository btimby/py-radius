test:
	coverage run tests.py

lint:
	flake8 radius.py

dependencies:
	pip install coverage coveralls flake8 wheel

travis: lint test

coveralls:
	coveralls -v
