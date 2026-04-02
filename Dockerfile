# Build stage
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /snitchproxy ./cmd/snitchproxy

# Runtime stage
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /snitchproxy /snitchproxy

EXPOSE 8080 9484

ENTRYPOINT ["/snitchproxy"]
