.PHONY: all tui nfqueue clean run-tui sync

all: tui nfqueue

tui:
	go build -o bin/euriclea-tui ./cmd/tui/

nfqueue:
	go build -o bin/nfqueue ./cmd/nfqueue/

clean:
	rm -f bin/euriclea-tui bin/nfqueue bin/extractv2 debug.log blacklist.txt
	rm -rf bin/

run-tui: tui
	sudo tcpdump -i any -n -U -w - | ./bin/euriclea-tui -host 127.0.0.1 -

sync:
	./scripts/sync_blacklist.sh
