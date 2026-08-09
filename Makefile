.PHONY: test demo

test:
	pytest -q

demo:
	agent-boundary demo
