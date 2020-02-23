## CS219: System Modelling Anteater with Z3

1. To install required packages run "pip3 install -r requirements.txt"
2. To run the program, python3 main.py -f routers.csv -t 1 -n 
	1. f --> file name for routers
	2. t --> 1 means reachability 2 --> loops
	3. n --> verbose - graph draw
3. Update routers.csv for network topology
4. Use 0.0.0.0/0 for *

-------------------------------------------------------------------------------------
### Loop example:

ID, prefix, fwd_to
1, 10.1.0.0/16, 2
2, 10.1.1.0/24, 3
2, 10.1.2.0/24, 4
4, 10.1.2.255/25, 5
5, 10.1.2.255/26, 6
6, 10.1.2.255/27, 7
6, 10.1.2.192/27, 8
7, 10.1.2.255/28, 4

### Reachability:

ID, prefix, fwd_to
1, 10.1.0.0/16, 2
2, 10.1.192.0/18, 3
3, 10.1.255.0/24, 4
4, 10.1.255.72/29, 5
5, 10.1.255.75/32, 6

### No loop (modified loop example):
1, 10.1.0.0/16, 2
2, 10.1.1.0/24, 3
2, 10.1.2.0/24, 4
4, 10.1.2.255/25, 5
5, 10.1.2.255/26, 6
6, 10.1.2.255/27, 7
6, 10.1.2.192/27, 8
7, 10.1.3.255/28, 4
9, 10.1.3.0/24, 7