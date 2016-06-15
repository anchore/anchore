#!/bin/bash

for i in devone devtwo devthree devfour devfive
do
if ( ! docker images | grep $i ); then
    docker build --no-cache=true -t $i $i
    docker tag $i:latest $i:apr15
fi
done

#for i in devone devthree devfive
#for i in devone
#do
#docker build --no-cache=true -t $i $i
#docker tag $i localhost:5000/$i
#docker push localhost:5000/$i
#docker rmi $i
#docker pull localhost:5000/$i
#docker tag localhost:5000/$i $i
#docker rmi localhost:5000/$i
#done


#for i in ubuntu:16.04 centos:7 centos:latest
#do
#docker tag $i localhost:5000/$i
#docker push localhost:5000/$i
#docker rmi $i
#docker pull localhost:5000/$i
#docker tag localhost:5000/$i $i
#docker rmi localhost:5000/$i
#done
