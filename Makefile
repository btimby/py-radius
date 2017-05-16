test:
	python tests.py

lint:
	flake8 radius.py

dependencies:
	pip install coverage coveralls flake8

travis: lint test

