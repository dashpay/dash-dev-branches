max=1000
for i in `seq 0 $max`
do
    # sends to 2
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8330 -rpcport=8331 sendtoaddress yYHyVdRaMDK7E4fTLf2bzeKw7fRyg1evZ1 0.1
    #sends to 3
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8332 -rpcport=8333 sendtoaddress yaStdWLEBSJvLWqQ9Nu7jzvz5VZxT5GgRM 0.1
    #sends to 4
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8334 -rpcport=8335 sendtoaddress yRkvzXnA39Nc24TRTeThFQi2VoBEHNv9w8 0.1
    # send to 1
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8336 -rpcport=8337 sendtoaddress yPATRLLvJzJgi3BL52n4yz73fB5ofVx33C 0.1

done
