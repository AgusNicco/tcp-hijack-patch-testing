#!/bin/bash
# Start, load, reload or stop the services run.sh measures, or browse the web.
#   usage: sudo services.sh start|reload|stop
#          sudo services.sh traffic|browse SECONDS OUTFILE
#
#   host       OpenSSH (the host's own sshd)
#   bridge     PostgreSQL, nginx (reuseport), FastAPI (uvicorn, 4 workers),
#              each in a container with a published port
#   host net   nginx (reuseport) and HAProxy (master-worker), in containers
#              that share the host's network namespace
#   hand-built hotrestart.py (an SO_REUSEPORT group replaced on SIGHUP) and
#              tproxy.py (a transparent proxy behind a TPROXY rule, in its own
#              network namespace with a client namespace in front of it)
#   desktop    Firefox (headless, in a container on the host network),
#              browsing real websites
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
STATE=/tmp/bindtests-reach
NS="ip netns exec"
mkdir -p "$STATE"

wait_for() {
	for _ in $(seq 60); do "$@" > /dev/null 2>&1 && return 0; sleep 1; done
	echo "not ready: $*" >&2
	return 1
}

start_tproxy() {
	ip netns add rt-proxy
	ip netns add rt-client
	ip link add rt-c type veth peer name rt-p
	ip link set rt-c netns rt-client
	ip link set rt-p netns rt-proxy
	ip -n rt-client addr add 10.200.0.1/24 dev rt-c
	ip -n rt-proxy addr add 10.200.0.2/24 dev rt-p
	for n in rt-client rt-proxy; do ip -n $n link set lo up; done
	ip -n rt-client link set rt-c up
	ip -n rt-proxy link set rt-p up
	ip -n rt-client route add default via 10.200.0.2
	# Connections from the client to any address, port 18200, are delivered
	# to the proxy's listeners on port 18201.
	$NS rt-proxy iptables -t mangle -A PREROUTING -p tcp --dport 18200 \
		-j TPROXY --on-port 18201 --tproxy-mark 1
	ip -n rt-proxy rule add fwmark 1 lookup 100
	ip -n rt-proxy route add local 0.0.0.0/0 dev lo table 100
	$NS rt-proxy python3 "$HERE/tproxy.py" 18201 > /dev/null 2>&1 &
	echo $! > "$STATE/tproxy.pid"
}

start() {
	docker run -d --name rt-postgres -e POSTGRES_PASSWORD=bindtests \
		-p 127.0.0.1:15432:5432 postgres:16
	docker run -d --name rt-nginx -p 127.0.0.1:18080:80 \
		-v "$HERE/nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx
	docker run -d --name rt-fastapi -p 127.0.0.1:18000:8000 bindtests-fastapi
	docker run -d --name rt-nginx-host --network host \
		-v "$HERE/nginx-host.conf:/etc/nginx/conf.d/default.conf:ro" nginx
	docker run -d --name rt-haproxy --network host \
		-v "$HERE/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" haproxy:2.9
	python3 "$HERE/hotrestart.py" 18100 > /dev/null 2>&1 &
	echo $! > "$STATE/hotrestart.pid"
	start_tproxy
	wait_for docker exec rt-postgres pg_isready -h 127.0.0.1 -U postgres
	docker exec rt-postgres pgbench -i -q -h 127.0.0.1 -U postgres postgres
	for url in 127.0.0.1:18080 127.0.0.1:18081 127.0.0.1:18443 127.0.0.1:18100; do
		wait_for curl -sf "http://$url/"
	done
	wait_for $NS rt-client curl -sf http://10.201.0.9:18200/
}

traffic() {
	local secs=$1 out=$2
	python3 "$HERE/load.py" "$secs" 8 127.0.0.1:18080 127.0.0.1:18081 \
		"[::1]:18081" 127.0.0.1:18443 127.0.0.1:18100 "[::1]:18100" > "$out.http" &
	$NS rt-client python3 "$HERE/load.py" "$secs" 4 10.201.0.9:18200 10.201.0.10:18200 10.201.0.11:18200 10.201.0.12:18200 > "$out.tproxy" &
	docker exec rt-postgres pgbench -h 127.0.0.1 -U postgres -c 8 -j 4 -C \
		-T "$secs" postgres > "$out.pgbench-container" 2>&1 &
	docker run --rm --network host -e PGPASSWORD=bindtests postgres:16 \
		pgbench -h 127.0.0.1 -p 15432 -U postgres -c 4 -j 2 -C -T "$secs" \
		postgres > "$out.pgbench-published" 2>&1 &
	local end=$(( $(date +%s) + secs )) n=0
	while [ "$(date +%s)" -lt "$end" ]; do
		ssh-keyscan -T 2 127.0.0.1 > /dev/null 2>&1 && n=$((n + 1))
	done
	echo "ssh-keyscan handshakes: $n" > "$out.ssh"
	wait
	cat "$out".* > "$out"
	rm -f "$out".*
}

browse() {
	local secs=$1 out=$2
	docker run --rm --network host bindtests-firefox "$secs" 15 \
		https://www.youtube.com/ \
		"https://www.youtube.com/watch?v=jNQXAC9IVRw" \
		"https://www.google.com/search?q=linux+kernel" \
		https://www.wikipedia.org/ \
		https://en.wikipedia.org/wiki/Linux_kernel \
		https://github.com/torvalds/linux \
		https://www.reddit.com/ \
		https://www.amazon.com/ \
		https://www.bbc.com/news \
		https://stackoverflow.com/questions > "$out"
}

reload() {
	docker exec rt-nginx nginx -s reload
	docker exec rt-nginx-host nginx -s reload
	docker kill -s USR2 rt-haproxy
	for _ in 1 2 3 4 5; do
		kill -HUP "$(cat "$STATE/hotrestart.pid")"
		sleep 1
	done
	docker restart rt-postgres rt-fastapi
	systemctl restart ssh.service
	sleep 5
}

stop() {
	for c in rt-postgres rt-nginx rt-fastapi rt-nginx-host rt-haproxy; do
		docker rm -f "$c"
	done
	for p in hotrestart tproxy; do
		[ -f "$STATE/$p.pid" ] && kill "$(cat "$STATE/$p.pid")"
		rm -f "$STATE/$p.pid"
	done
	ip netns del rt-client
	ip netns del rt-proxy
	sleep 2
}

cmd=$1
shift
"$cmd" "$@"
