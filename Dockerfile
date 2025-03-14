FROM golang@sha256:fa145a3c13f145356057e00ed6f66fbd9bf017798c9d7b2b8e956651fe4f52da as builder

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
