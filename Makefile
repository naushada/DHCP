DHCP_INC=-I../inc
TCP_SRC=
HTTP_SRC=
DHCP_SRC=dhcp_main.c
CC=gcc
CFLAGS=-Wall -g
OBJ=DHCP
SRC=

$(OBJ):	$(SRC)
	$(CC) $(CFLAGS) $(DHCP_INC) $(DHCP_SRC)  -o $(OBJ)


clean:
	rm -fr $(OBJ)
