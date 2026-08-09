# Contributing

Contributions should keep the project focused on effective-boundary measurement.

A new probe should be:

- safe by default;
- based on synthetic resources where possible;
- deterministic;
- explicit about what an `allow` or `deny` result proves;
- covered by tests;
- free of real credential collection.

A new agent adapter must not weaken that agent's sandbox or permission settings in order to obtain a result.

Run before submitting:

```bash
python3 -m pip install -e '.[dev]'
pytest -q
agent-boundary demo
```
