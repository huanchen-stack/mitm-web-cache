#!bin/bash

# install mongo
brew tap mongodb/brew
brew install mongodb-community


# start mongo
brew services start mongodb/brew/mongodb-community


# stop mongo
brew services stop mongodb/brew/mongodb-community


# check log
tail -f /usr/local/var/log/mongodb/mongo.log


# change config
nano /usr/local/etc/mongod.conf


# verify port listening
lsof -iTCP:27017 -sTCP:LISTEN