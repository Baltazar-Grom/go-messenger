FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o messenger main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/messenger .
COPY --from=builder /app/index.html .
EXPOSE 8080
CMD ["./messenger"]