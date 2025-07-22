NAME_SHORT:="tr-05-sumo-logic-log-management"
NAME:=ciscosecurity/$(NAME_SHORT)
PORT:="9090"
PLATFORM=--platform linux/amd64,linux/arm64
VERSION:=$(shell python3 scripts/pq.py poetry version)

all: env build test check

run: # app locally
	cd code; python -m app; cd -

# Docker
build: stop_name
	docker buildx build $(PLATFORM) -t $(NAME):$(VERSION) -t $(NAME):latest .
start: build
	docker run -dp $(PORT):$(PORT) --name $(NAME_SHORT) $(NAME):$(VERSION)
stop:
	docker rm -f $(shell docker ps -aq) > /dev/null; true
stop_name:
	docker stop $(NAME_SHORT); docker rm $(NAME_SHORT); true

release: build
	docker login
	docker image push --all-tags $(NAME)
	@echo "https://hub.docker.com/repository/docker/$(NAME)/tags"

# Tools
env: pyproject.toml
	python3 -m venv .venv; . ./.venv/bin/activate && poetry lock && poetry install
lint: pyproject.toml
	black code/ scripts/; flake8 code/ scripts/; mypy code/ scripts/
bandit: pyproject.toml
	bandit -r code/ --exclude tests
radon: pyproject.toml
	radon cc code/ -s -a

# Tests
check:
	curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --
	docker scout cves $(NAME) --only-fixed
	pip-audit
test: lint
	cd code; coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report --fail-under=80; cd -
test_lf:
	cd code; coverage run --source api/ -m pytest --verbose -vv --lf tests/unit/ && coverage report -m --fail-under=80; cd -