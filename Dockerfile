FROM golang:1.25-alpine

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . .

RUN go build -o /ipc-go cmd/ipc/main.go

EXPOSE 8000

CMD [ "sh", "-c", "exec /ipc-go --account-id $ACCOUNT_ID --password $PASSWORD --admin-key $ADMIN_KEY $KEYS" ]