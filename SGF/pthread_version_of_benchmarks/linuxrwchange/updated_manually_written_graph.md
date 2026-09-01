# Shared Locations
LOC mylock
LOC shareddata
LOC value

# Event: ID TID  Kind  Loc  Mode
// e1: this is for creating a union called mylock
E,e1,0,W,mylock,NA

E,e2,0,W,shareddata,NA
E,e3,0,W,value,NA

E,e4,0,W,mylock,NA

E,e5,1,R,value,Rlx

E,e6,1,W,value,Rlx

// read_lock(&mylock) func call
E,e7,1,RMW,mylock,Acq
E,e8,1,RMW,mylock,Rlx
E,e9,1,R,mylock,Rlx
E,e10,1,RMW,mylock,Rlx

E,e11,1,R,shareddata,NA

// read_unlock(&mylock) func call
E,e12,1,RMW,mylock,Rel

// write_lock(&mylock) func call
E,e13,1,RMW,mylock,Acq
E,e14,1,RMW,mylock,Rlx
E,e15,1,R,mylock,Rlx
E,e16,1,RMW,mylock,Rlx

E,e17,1,W,value,Rlx
E,e18,1,W,shareddata,NA

// write_unlock(&mylock) func call
E,e19,1,RMW,mylock,Rel

E,e20,2,R,value,Rlx

E,e21,2,W,value,Rlx

// read_lock(&mylock) func call
E,e22,2,RMW,mylock,Acq
E,e23,2,RMW,mylock,Rlx
E,e24,2,R,mylock,Rlx
E,e25,2,RMW,mylock,Rlx

E,e26,2,R,shareddata,NA

// read_unlock(&mylock) func call
E,e27,2,RMW,mylock,Rel

// write_lock(&mylock) func call
E,e28,2,RMW,mylock,Acq
E,e29,2,RMW,mylock,Rlx
E,e30,2,R,mylock,Rlx
E,e31,2,RMW,mylock,Rlx

E,e32,2,W,value,Rlx
E,e33,2,W,shareddata,NA

// write_unlock(&mylock) func call
E,e34,2,RMW,mylock,Rel




# Control Flow edges
CF e1 e2
CF e2 e3
CF e3 e4
CF e4 e6
CF e4 e22

CF e6 e6    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e6 at random

CF e6 e7    //if    (read_lock)
CF e6 e14   //else  (write_lock)

CF e7 e8
CF e7 e12   //without going into while loop

CF e8 e9

//not adding CF e9 e9 since it is just a sched_yield

CF e9 e11
CF e11 e8    //loop
CF e11 e12   //come out of loop

CF e12 e13

CF e13 e6
CF e13 e21

CF e14 e15
CF e14 e18  //without going into while loop

CF e15 e16

//not adding CF e16 e16 since it is just a sched_yield

CF e16 e17
CF e17 e15  //loop
CF e17 e18  //come out of loop

CF e18 e19
CF e19 e5

CF e5 e6
CF e5 e21

//Thread 2
CF e22 e22    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e22 at random

CF e22 e23    //if    (read_lock)
CF e22 e29   //else  (write_lock)

CF e23 e24
CF e23 e27   //without going into while loop

CF e24 e25

//not adding CF e25 e25 since it is just a sched_yield

CF e25 e26
CF e26 e24    //loop
CF e26 e27   //come out of loop

CF e27 e28

CF e28 e22
CF e28 e20

CF e29 e30
CF e29 e33  //without going into while loop

CF e30 e31

//not adding CF e31 e31 since it is just a sched_yield

CF e31 e32
CF e32 e30  //loop
CF e32 e33  //come out of loop

CF e33 e34
CF e34 e35

CF e35 e22
CF e35 e20



//changes made: e19 -> e5, incremented all

// e35 -> e20