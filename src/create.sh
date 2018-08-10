output_1=`./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8330 -rpcport=8331 getnewaddress`
output_2=`./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8332 -rpcport=8333 getnewaddress`
output_3=`./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8334 -rpcport=8335 getnewaddress`
output_4=`./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8336 -rpcport=8337 getnewaddress`

max=100
for i in `seq 0 $max`
do
    # sends to 2
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8330 -rpcport=8331 sendtoaddress $output_2 0.01
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8330 -rpcport=8331 sendtoaddress $output_3 0.01
    ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8330 -rpcport=8331 sendtoaddress $output_4 0.01
    #sends to 3
    # ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8332 -rpcport=8333 sendtoaddress $output_3 0.1
    #sends to 4
    # ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8334 -rpcport=8335 sendtoaddress $output_4 0.1
    # send to 1
    # ./dash-cli -regtest -daemon -use-grapheneblocks=1 -debug -port=8336 -rpcport=8337 sendtoaddress $output_1 0.1

done
