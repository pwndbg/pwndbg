help:
	@echo "Please check the content of the Makefile"

dc/test:
	docker-compose run main ./tests.sh

dc/run:
	docker-compose run main bash

dc/rebuild:
	docker-compose build main
