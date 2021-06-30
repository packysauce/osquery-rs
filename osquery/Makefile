
.DEFAULT: all

OSQUERY_VERSION ?= 4.9.0

osquery.thrift:
	curl -sSfLO https://raw.githubusercontent.com/osquery/osquery/${OSQUERY_VERSION}/osquery/extensions/thrift/osquery.thrift

src/gen/osquery.rs: osquery.thrift
	mkdir -p src/gen
	thrift -out src/gen --gen rs -r osquery.thrift

.PHONY: all
all: src/gen/osquery.rs osquery.thrift

.PHONY: clean
clean:
	rm src/gen/osquery.rs osquery.thrift

