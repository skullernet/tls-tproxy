CFLAGS := -O2 -Wall -Wextra
LDLIBS := -ldill

tls-tproxy: tls-tproxy.c
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS) $(LDLIBS)

.PHONY: clean

clean:
	rm -f tls-tproxy
