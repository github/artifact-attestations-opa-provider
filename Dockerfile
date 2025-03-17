# this is alpine with go and make, but cached to not be hit by docker rate
# limits
FROM ghcr.io/kommendorkapten/ghademo:builder as builder

WORKDIR /tmp/fsn

COPY . .
RUN go mod download
RUN make build

# this is alpine, but cached to not be hit by docker rate limits
FROM ghcr.io/kommendorkapten/ghademo:runtime

WORKDIR /
RUN mkdir /certs
COPY --from=builder /tmp/fsn/aaop .
COPY --from=builder /tmp/fsn/certs/tls.crt /tmp/fsn/certs/tls.key /certs/

CMD /aaop
