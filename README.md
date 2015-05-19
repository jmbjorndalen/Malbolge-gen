# Malbolge-gen


[Malbolge](http://en.wikipedia.org/wiki/Malbolge) is a programming language that was designed to be difficult to program in. In fact, it took two years before the first Malbolge program managed to print "Hello world", except that it didn't get the capitalization correct. Malbolge is one of the [esoteric programming languages](http://en.wikipedia.org/wiki/Esoteric_programming_language), of which other examples are Brainfuck and INTERCAL (famous for its "COME FROM" instruction). 

I first started playing with this for pure entertainment, then to explore whether it would be possible to write a parallel program to search for a short Malbolge program printing a given text. After playing with an Malbolge interpreter and some ideas found on the net, I decided that my first approach would not work. Searching for a short program that writes the correct text by trying different combinations of instructions, and using the interpreter to check the results is simply too time consuming. There are too many possible combinations, even if I try to eliminate branches by scoring the results and killing off branches that emit any erroneous characters. 

Turning the problem around, I made a branching and searching interpreter. The interpreter starts with an empty program (nothing is filled in yet) and a target output string. Every time the interpreter tries to read from a new location in memory, the state of the interpreter is pushed onto a stack. Then I simply try to continue running the interpreter with all of the possible values that could be read from that memory location one by one. 

In other words, I recursively try all possible execution paths of the program rather than recursively generating all possible programs. Every time I find an execution path that prints the correct output, I compare it with the currently best program and keep the best version, mainly scored for total program length. 

To avoid following long executions that never print anything useful, I continuously score the execution and kill off program traces that either create too many branches before printing a new character, or read from a location in memory that would create a longer program than the currently shortest program. I also kill off branches that print out the wrong output. 

The result is an interpreter that finds fairly short Malbolge programs. The first 'Hello world' was found after 3 seconds on one of the cluster nodes (a 3.2GHz Intel P4 Prescott) we had at the time I wrote this program (2006 or earlier). 
