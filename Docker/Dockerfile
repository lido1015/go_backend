# syntax = docker/dockerfile:1.0-experimental
FROM golang:1.15.8-alpine

RUN apk add --no-cache git make upx

RUN --mount=type=secret,id=github-token,dst=/github-token git config --global url."https://stdevAdrianPaez:$(cat /github-token)@github.com".insteadOf "https://github.com"

RUN git clone https://github.com/NODO-UH/gestion-go

WORKDIR /go/gestion-go

RUN git checkout develop

RUN make build