FROM ghcr.io/kommendorkapten/ghademo:builder as builder

WORKDIR /tmp/fsn

COPY . .
RUN make build

# FROM alpine:latest

#WORKDIR /
RUN mkdir /certs
#COPY --from=builder /tmp/fsn/cosign-gatekeeper-provider .
#COPY --from=builder /tmp/fsn/certs/tls.crt /tmp/fsn/certs/tls.key /certs/

RUN cp /tmp/fsn/aaop /
RUN cp /tmp/fsn/certs/tls.crt /tmp/fsn/certs/tls.key /certs/

CMD /aaop
