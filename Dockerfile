FROM golang:1.9.7-alpine3.7 AS builder

WORKDIR /go/src/github.com/swgiacomelli/gonetmon
COPY . .

RUN go mod init github.com/swgiacomelli/gonetmon
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o gonetmond -ldflags '-s -w -extldflags "-static"' .

FROM scratch
COPY --from=builder /go/src/github.com/swgiacomelli/gonetmon/gonetmond /app/

ENTRYPOINT ["/app/gonetmond"]