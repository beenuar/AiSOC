# AiSOC Demo Event Producer
# Multi-stage Go build → tiny distroless runtime image.
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/demo-producer .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /out/demo-producer /demo-producer
USER nonroot:nonroot
ENTRYPOINT ["/demo-producer"]
