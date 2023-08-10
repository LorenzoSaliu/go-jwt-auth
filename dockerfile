FROM golang:1.20.7-alpine

RUN apk add --no-cache make

RUN mkdir /app

ADD . /app

WORKDIR /app

RUN make build
RUN chmod +x /app/bin/auth

CMD [ "/app/bin/auth" ]


