/* 
 * Searches for a short Malboge program that prints the target string
 * by using a branch-on-memory-read based interpreter: every time a
 * new memory location is read, the interpreter branches off in all
 * possible directions (for all possible values of that location),
 * recursively searching for the shortest Malbolge program.
 * 
 * In effect, the program recursively searches through all possible
 * execution paths of a Malbolge program to find a program that prints the
 * desired output.
 * 
 * (C) John Markus Bjørndalen, 2006
 * 
 * The interpreter code is based on the Malbolge interpreter by Ben
 * Olmstead (1998).
 * 
 * NB: If you're mad enough to want to write Malbolge programs in the
 * first place, you should be cabable of finding out where the output
 * files are stored and how to modify this program to search for
 * anything else than "Hello" ;-)
 */ 

#include <string>
#include <iostream>
#include <exception>
#include <fstream>
#include <sstream>
#include "utils.h"
#include <map>
#include <stack>

#define MAX_TRIT  59049                  // Max 10-trit value is 59049 = 3^10


/* ------------------- parameters to tune - begin ------------------- */ 
#define MAX_OSEARCH            10        // max number of new emits between output chars 
#define MAX_SEARCH_ITERS 10000000        // Max number of emits in total. May not be needed any more

std::string TARGET        = "Hello world"; 
int     maxAllowedProgLen = 250;  // or MAX_TRIT
/* ------------------- parameters to tune - end ------------------- */ 

enum MB_Exception { 
    BRANCH_DEPTH_EXCEPTION = 42, 
    ILLEGAL_ADDR_EXCEPTION, 
    MAX_APLEN_EXCEPTION
}; 

// Stages of the interpreters main loop, used in the interpreter interpreter
enum InterpreterStage { 
    STAGE_IFETCH = 0,         // instruction fetch and check for infinity
    STAGE_EXEC,               // execute given instruction
    STAGE_MODMEM,             // modify location of memory that the Rc register currently points at
    STAGE_MODINC,             // modulo increment instruction and data pointer
    // 
    STAGE_NUMSTAGES,          // Number of stages
}; 


/* ------------------------------------------------------------ */ 

/* 
 * the xlat1 table translates one of the 8 legal positions to opcodes for malbolge. 
 * instead of going through that translation table, I use the positions as opcodes directly. 
 * 
 */ 
enum { 
    OP_READ_DATA =  7,   // 'j'
    OP_READ_IP   = 65,   // 'i'
    OP_ROT_RIGHT =  6,   // '*'
    OP_TERNARY   = 29,   // 'p'
    OP_WRITE     = 66,   // '<'
    OP_READ      = 84,   // '/'
    OP_TERMINATE = 48,   // 'v'
    OP_NOP       = 35,   // 'o'   - or any other translation
    NUM_OPCODES  = 8,    // Number of operations in malbolge
}; 

// True if it's a legal Malbolge operation
static inline int legal_op(unsigned int op)
{
    switch(op) { 
    case OP_READ_DATA:
    case OP_READ_IP:
    case OP_ROT_RIGHT:
    case OP_TERNARY:
    case OP_WRITE:
    case OP_READ:
    case OP_TERMINATE:
    case OP_NOP:
	return 1; 
    }
    return 0; 
}

// Decrypt/decode the contenct in the memory as a malbolge operation.
// The pos/addr in memory is a necessary part of the operation. 
static inline unsigned short decode_op(unsigned short val, unsigned short pos)
{
    return (val - 33 + pos) % 94; 
}

// Given a legal opcode, encode it such that decode_op brings back the original opcode. 
static inline unsigned short encode_op(unsigned short opcode, unsigned short pos)
{
    // Need to convert to ints to get correct treatment of the expression using modulo arithmetic. 
    int o = opcode; 
    int p = pos; 
    return 33 + imod(o - p, 94);
}

// Used by malbolge to modify the instruction the IP(c) is currently pointing at. 
static const char xlat2[] =
  "5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1C"
  "B6v^=I_0/8|jsb9m<.TVac`uY*MK'X~xDl}REokN:#?G\"i@";


// Perform a tritwise op on the values x and y
static inline unsigned short op(unsigned short x, unsigned short y)
{
    unsigned short i = 0, j;
    static const unsigned short p9[5] =
	{ 1, 9, 81, 729, 6561 };  // Tritvals :  1=3**0, 9=3**2, 81=3**4, 729=3**6, 6561=3**8
    static const unsigned short o[9][9] =
	{
	    { 4, 3, 3, 1, 0, 0, 1, 0, 0 },
	    { 4, 3, 5, 1, 0, 2, 1, 0, 2 },
	    { 5, 5, 4, 2, 2, 1, 2, 2, 1 },
	    { 4, 3, 3, 1, 0, 0, 7, 6, 6 },
	    { 4, 3, 5, 1, 0, 2, 7, 6, 8 },
	    { 5, 5, 4, 2, 2, 1, 8, 8, 7 },
	    { 7, 6, 6, 7, 6, 6, 4, 3, 3 },
	    { 7, 6, 8, 7, 6, 8, 4, 3, 5 },
	    { 8, 8, 7, 8, 8, 7, 5, 5, 4 },
	};
    for (j = 0; j < 5; j++)
	i += o [y / p9[j] % 9] [x / p9[j] % 9] * p9[j];
    return (i);
}

/* ------------------------------------------------------------ */ 

/* I'm using an STL map to implement a sparse array. This gives me a
 * 10-fold increase in total execution speed speed from saving memory
 * bandwidth when I push and pop copies of the MBSearch object on the
 * stack.
 */ 
typedef std::map<unsigned int,unsigned int> MBMemory; 

class MBSearch {
public:
    unsigned short Ra, Rc, Rd;        // Registers

    int   nFetches;                   // Number of new fetches (that caused a branch in the search algorithm)
    int   curNewMem;                  // current position we had to create a new memory op at 
    int   curNewOP;                   // which of the opcodes did we currently write
    int   odepth;                     // current depth / number of new instructions since last output
    
    MBMemory mem;                     // Current content 
    MBMemory orig;                    // The program value we wrote when a read fault was triggered
    int highestAddrRead;              // Highest address read

    InterpreterStage iStage;          // Current stage of the interpreter
    unsigned short instr;             // used internally in the loop, currently read instruction

    std::string output; 

    // Return values from doExec
    enum {
	RES_OK, 
	RES_INFINITE_LOOP,
	RES_TRIED_INPUT,
	RES_MAX_ITERS,
	RES_WRITE_MISMATCH,
	RES_ERROR,
	RES_BRANCH_DEPTH,
    }; 

    void initExec();
    int doExec(); 

    // read and write functions for the interpreters memory
    unsigned short getMem(unsigned short addr); 
    unsigned short storeMem(unsigned short addr, unsigned short val); 
    
    // Insert a decoded program (simplifies auto-generating malbolge programs)
    int insertDecodedProg(unsigned short *prog, int len);

    // Highest memory address that was accessed by the program. No need to store anything after this
    int maxMemLoc() { return highestAddrRead; }    

    // Dump the current program to a given file, inserting NOPs in memory locations that 
    // were not visited.
    void dumpProgram(std::string fname); 
}; 

// MBSearch objects are pushed and popped from this stack to implement recursive execution path searches
std::stack<MBSearch*> globalStack; 

/* This is a list of the sequence of Malbolge opcodes that we try in the searching interpreter. 
 * NB: the WRITE (=print) operation is put first, to favorise program output. In my limited testing, this 
 * has resulted in finding the targets faster. 
 */ 
unsigned short MalbolgeOps[] = {
    OP_WRITE, // nb
    OP_READ_DATA, 
    OP_READ_IP,
    OP_ROT_RIGHT,
    OP_TERNARY,
    OP_READ,
    OP_TERMINATE,
    OP_NOP
};


/* ------------------------------------------------------------ */ 

/* 
 * Retrieves from the memory, generating a branch exception every time a new 
 * location is visited. 
 */ 
unsigned short MBSearch::getMem(unsigned short addr)
{
    if (addr >= MAX_TRIT)
    { 
	//std::cerr << "MBSearch::getMem called with addr " << addr << " with is outside legal bounds\n";
	throw ILLEGAL_ADDR_EXCEPTION; // program made an illegal reference, which will not fare well with the original interpreter, so abort this branch
    }
    if (addr >= maxAllowedProgLen) 
	throw MAX_APLEN_EXCEPTION;
    
    if (addr > highestAddrRead)
	highestAddrRead = addr; 
    
    MBMemory::iterator pos = mem.find(addr); 
    if (pos != mem.end())
	return pos->second;  // already have it

    // Reading a new memory location that has never been visited before. 
    // First, check whether we have branched out too deeply before omitting chars
    ++odepth; 
    if (odepth > MAX_OSEARCH)
	throw BRANCH_DEPTH_EXCEPTION; 

    // Simply fill in the first possible OP, then store this object on the stack, allowing the main loop to 
    // pick it up again and modify it later (restarting the object with the next possible instruction). 
    curNewMem = addr;         // keep track of addr, so main loop can modify this instruction
    curNewOP  = 0;            // we're currently using the first one
    orig[addr] = mem[addr]  = encode_op(MalbolgeOps[curNewOP], addr);
    ++nFetches;

    // Store a copy of this one on the stack
    globalStack.push(new MBSearch(*this));     // default copy constructor is ok

    return mem[addr];
}

unsigned short MBSearch::storeMem(unsigned short addr, unsigned short val)
{
    // NB: writes to an addr always occurs after a read to the same addr, so we never have to consider path branching 
    // or any other recording here. 
    if (addr >= MAX_TRIT)
    { 
	std::cerr << "MBSearch::storeMem called with addr " << addr << " with is outside legal bounds\n";
	throw ILLEGAL_ADDR_EXCEPTION; // program made an illegal reference, which will not fare well with the original interpreter, so abort this branch
    }
    if (addr >= maxAllowedProgLen) 
	throw MAX_APLEN_EXCEPTION;

    mem[addr] = val;
    return 0; 
}

int MBSearch::doExec()
{
    const long long MAX_ITERS = 100000000LL; 
    long long iters; 
    try
    { 
	for (iters = 0; iters < MAX_ITERS; iters++) // Guard againt infinite loops
	{ 
	    switch(iStage) { 
	    case STAGE_IFETCH:    // instruction fetch
		 instr = getMem(Rc); 
		// Check for infinity: trying to execute values outside the 94-range causes an infinite loop!
		if (instr < 33 || instr > 126) 
		    return RES_INFINITE_LOOP; 
		break; 
	    case STAGE_EXEC:      // execute given instruction
		// Decode op to NOP or one of the 8 ops. 
		switch (decode_op(instr, Rc))
		{
		case OP_READ_DATA:  // read data register from current 
		    Rd = getMem(Rd);
		    break;
		case OP_READ_IP:  // jump to addr 
		    Rc = getMem(Rd);
		    break;
		case OP_ROT_RIGHT:  // rotate right 1, lstrit=> mstrit (3**9 = 19683)
		{
		    unsigned short t = getMem(Rd); 
		    Ra = t / 3 + t % 3 * 19683;
		    storeMem(Rd, Ra);
		    break; 
		}
		case OP_TERNARY:  // run ternary operator on two values
		    Ra = op(Ra, getMem(Rd));
		    storeMem(Rd, Ra);
		    break;
		case OP_WRITE:  // output accumulator as a character
		{
		    // Checks whether this is a 'good' character, otherwise abort!
		    odepth = 0; 
		    char c = (char) Ra; 
		    if ((output.length() >= TARGET.length()) ||  // too long string
			(c != TARGET[output.length()]))          // wrong character
			return RES_WRITE_MISMATCH; 
		    output += c; 
		    break;
		}
		case OP_READ:  // We don't allow input from stdin in the program
		    return RES_TRIED_INPUT; 
		case OP_TERMINATE:  // terminate program
		    return RES_OK;
		case OP_NOP:
		default: // Unspecified operatins correspond to NOPs in the original interpreter
		    break;  
		}
		break; 
	    case STAGE_MODMEM:   { // modify location of memory that the Rc register currently points at
		// Modify op at position. Note that all chars in xlat2 are in the legal range for ops: 33..126
		// So, an OP will always be translated into an OP (either a NOP or the other 8 ops)
		int addr = getMem(Rc); 
		if (addr < 33 || (addr > (95+33)))
		{ 
		    // Pruning search paths that result in accesses out of bounds for xlat2
		    // NB: This happens very often when we search for programs, so we need to explicitly prune these
		    // paths as they will not execute correctly if we try them with the interpreter.
		    return RES_ERROR; 
		}
		storeMem(Rc, xlat2[addr - 33]);	
		break; 
	    }
	    case STAGE_MODINC:    // modulo increment instruction and data pointer
		Rc = modInc(Rc, MAX_TRIT); 
		Rd = modInc(Rd, MAX_TRIT); 
		break; 
	    default:
		std::cerr << "ERROR, interpreter interpreter with illegal stage " << iStage << std::endl; 
		exit(-1);
	    } 
	    iStage = (InterpreterStage) modInc(iStage, STAGE_NUMSTAGES); 
	}
    }
    catch (MB_Exception e)
    {
	switch (e) { 
	case BRANCH_DEPTH_EXCEPTION:
	case MAX_APLEN_EXCEPTION:
	    return RES_BRANCH_DEPTH;
	default:
	    return RES_ERROR;
	}
    }
    return RES_MAX_ITERS;
}

void MBSearch::initExec()
{
    Ra = 0;
    Rc = 0; 
    Rd = 0; 
    output = ""; 
    odepth = 0; 
    iStage = STAGE_IFETCH; 
}

void MBSearch::dumpProgram(std::string fname)
{
    std::ofstream f(fname.c_str(), std::ios::trunc); 

    for (int i = 0; i <= highestAddrRead; i++) 
    {
	MBMemory::iterator pos = mem.find(i); 
	if (pos == mem.end())
	    f << (char) (encode_op(OP_NOP, i));   // Since these aren't fetched, I could dump anything here
	else
	    f << (char) orig[i]; 
    }
}

/* ------------------------------------------------------------ */ 


void printCurOutput(MBSearch *cur, int newline = true)
{
    std::cout << "\r   output from program '" << cur->output << "' "
	      << "maxMemLoc " << cur->maxMemLoc() 
	      << " nFetches " << cur->nFetches << "                     "; 
    if (newline)
	std::cout << std::endl;
}      


/* Dumps a program to a filename made from the prefix, the length of the program and the suffix .mb */
void storeProgram(std::string prefix, MBSearch * prog) 
{
    std::ostringstream str; 
    str << prefix << prog->maxMemLoc() << ".mb";
    prog->dumpProgram(str.str());
}

int main(int argc, char *argv[]) 
{
    MBSearch *mb = new MBSearch();
    mb->initExec();
    mb->doExec(); // get the initial execution started.. TODO: this is wrong. I'm ignoring the result of the first path, even if it could be correct (however unlikely)

    MBSearch *bestProg = NULL; 

    std::cout << "Parameters for the generator\n"; 
    std::cout << "    TARGET             '" << TARGET << "'\n";
    std::cout << "    MAX_OSEARCH        " << MAX_OSEARCH << std::endl; 
    std::cout << "    MAX_SEARCH_ITERS   " << MAX_SEARCH_ITERS << std::endl; 
    std::cout << "    maxAllowedProgLen  " << maxAllowedProgLen << std::endl;
    std::cout << "    sizeof(MBSearch)   " << sizeof(MBSearch) << std::endl; 
    std::cout << "    sizeof(xlat2)      " << sizeof(xlat2) << std::endl; 
    
    long long start = get_tod_usecs();    // start of search
    long long prevOut = start;            // previous output time
    for (int i = 0; i < MAX_SEARCH_ITERS && !globalStack.empty(); i++)
    { 
	MBSearch *cur = globalStack.top();
	globalStack.pop();

	if (bestProg != NULL && cur->maxMemLoc() >= bestProg->maxMemLoc())
	{
	    // No point in continuing along a longer code path. 
	    delete cur; 
	    continue; 
	}
	
	++cur->curNewOP; 
	if (cur->curNewOP >= NUM_OPCODES)
	{ 
	    // exchausted our options with this branch
	    delete cur; 
	    continue; 
	}

	// First, modify the current instruction
	int addr = cur->curNewMem;
	cur->orig[addr] = cur->mem[addr] = encode_op(MalbolgeOps[cur->curNewOP], addr);

	// prepare for next round, push a copy back on the stack before we execute with the current search path
	globalStack.push(new MBSearch(*cur));
	int ret = cur->doExec();
	if (i % 50000 == 0)
	{ 
	    // every once in a while, provide some output for the user
	    std::cout << "\n   done with search # " << i << " DT " << timeSince(prevOut) << std::endl;
	    printCurOutput(cur); 
	    prevOut = get_tod_usecs(); 
	}
	if (ret == MBSearch::RES_OK && cur->output.compare(TARGET) == 0)
	{ 
	    // Found a correct program that terminates after printing the target string.
	    // Check if it's better than the currently best program, and store the result
	    if ((bestProg == NULL) || (cur->maxMemLoc() < bestProg->maxMemLoc()))
	    { 
		if (bestProg)
		    delete bestProg; 
		bestProg = new MBSearch(*cur); 

		std::cout << "\nSTORING new best program with score " << bestProg->maxMemLoc()
			  << " after " << timeSince(start) << " seconds" << std::endl; 
		printCurOutput(cur); 
		storeProgram("/tmp/t-", bestProg); 
		maxAllowedProgLen = bestProg->maxMemLoc();
	    }
	}
	delete cur; 
    };
    return 0; 
}
