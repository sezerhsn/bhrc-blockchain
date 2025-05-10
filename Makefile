.PHONY: test coverage clean

test:
	pytest tests/ --disable-warnings -v

coverage:
	pytest --cov=bhrc_blockchain tests/

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -exec rm -r {} +
	rm -rf .pytest_cache .coverage htmlcov

