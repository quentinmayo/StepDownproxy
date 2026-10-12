FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY examples/demo ./examples/demo
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stepdownproxy ./cmd/stepdownproxy && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/demo-upstream ./examples/demo

FROM scratch AS demo
COPY --from=build /out/demo-upstream /demo-upstream
USER 65532:65532
ENTRYPOINT ["/demo-upstream"]

FROM scratch AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/stepdownproxy /stepdownproxy
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/stepdownproxy"]
