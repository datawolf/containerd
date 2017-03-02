all:
	gcc -g  -o docker-containerd-shim main.c utils.c mainloop.c -lyajl
	cp ./docker-containerd-shim ../bin/containerd-shim
clean:
	rm -fr docker-containerd-shim
