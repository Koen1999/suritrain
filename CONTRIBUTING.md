# Contributing

## Preparing the development environment

To install packages required for running tests and linting, run the following command:

```bash
pip install -r djangosite/requirements.txt
```

Note that you may want to setup a [virtual environment (venv)](https://docs.python.org/3/library/venv.html) before installing dependencies to prevent conflicts.

## Linting

To automatically fix some linting issues and check for remaining issues, run the following commands:

```bash
black .
ruff check . --fix
pyright
```

### Markdownlint

If you made changes to `.md` file and want to lint them locally, you have to install `markdownlint` using `npm`.

```bash
npm install -g markdownlint-cli2
```

Now you can lint markdown files using to automatically detect all issues and fix some:

```bash
markdownlint-cli2 --fix "**/*.md"
```
