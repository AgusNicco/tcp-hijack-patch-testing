FROM debian:12
RUN apt-get update && apt-get install -y --no-install-recommends firefox-esr ca-certificates \
	&& rm -rf /var/lib/apt/lists/* && useradd -m browser
COPY browse.sh /browse.sh
USER browser
ENTRYPOINT ["/bin/sh", "/browse.sh"]
