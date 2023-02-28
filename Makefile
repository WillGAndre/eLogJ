.PHONY: build run stop clean show

build:
	sudo docker buildx build --platform=linux/amd64 -t elogj .
	sudo docker ps

run:
	sudo docker exec -it buildx_buildkit_qemu0 /bin/sh

stop:
	sudo docker stop buildx_buildkit_qemu0
	sudo docker ps

clean:
	sudo docker image prune --force

show:
	sudo docker inspect buildx_buildkit_qemu0