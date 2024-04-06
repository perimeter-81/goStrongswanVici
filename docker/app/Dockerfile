# Docker image for building the Go app
FROM golang:latest

WORKDIR /app
ADD ./ ./

RUN go build ./cmd/main.go