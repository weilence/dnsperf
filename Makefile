.PHONY: dist

dist:
	python setup.py bdist_wheel
	pip download -r requirements.txt -d dist