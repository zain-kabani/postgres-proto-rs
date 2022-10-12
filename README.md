# Postgres Proto RS

A project to help you parse the postgres wire protocol in rust!

Inspired by [jackc/pgproto3](https://github.com/jackc/pgproto3)

## Please refer to the examples folder for an example of creating a simple postgres proxy server

The network module has both standard and tokio implementations to get and send client or server messages

The messages module contains the logic for reading and parsing the postgres wire messages. 

*Note:* Not very message type has parsing implemented. Contributions are welcome!
