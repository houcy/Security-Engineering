all: make_dir list getacl setacl fget fput  

make_dir: make_dir.c
	cc make_dir.c -o make_dir 
getacl: getacl.c
	cc getacl.c -o getacl 
setacl: setacl.c
	cc setacl.c -o setacl
list: list.c
	cc list.c -o list
fget: fget.c
	cc fget.c -o fget
fput: fput.c
	cc fput.c -o fput

clean:
	rm make_dir 
	rm getacl 
	rm list
	rm fput
	rm fget
	rm setacl
