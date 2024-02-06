#!/bin/sh

docker build . -t l3hctf/treasure_hunter
docker run -p 0.0.0.0:31778:31778/tcp --name l3h_treasure_hunter l3hctf/treasure_hunter
