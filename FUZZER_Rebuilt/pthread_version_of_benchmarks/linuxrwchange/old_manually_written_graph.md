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

E,e5,1,W,value,Rlx

// read_lock(&mylock) func call
E,e6,1,RMW,mylock,Acq
E,e7,1,RMW,mylock,Rlx
E,e8,1,R,mylock,Rlx
E,e9,1,RMW,mylock,Rlx

E,e10,1,R,shareddata,NA

// read_unlock(&mylock) func call
E,e11,1,RMW,mylock,Rel

// write_lock(&mylock) func call
E,e12,1,RMW,mylock,Acq
E,e13,1,RMW,mylock,Rlx
E,e14,1,R,mylock,Rlx
E,e15,1,RMW,mylock,Rlx

E,e16,1,W,value,Rlx
E,e17,1,W,shareddata,NA

// write_unlock(&mylock) func call
E,e18,1,RMW,mylock,Rel

E,e19,1,R,value,Rlx

E,e20,2,W,value,Rlx

// read_lock(&mylock) func call
E,e21,2,RMW,mylock,Acq
E,e22,2,RMW,mylock,Rlx
E,e23,2,R,mylock,Rlx
E,e24,2,RMW,mylock,Rlx

E,e25,2,R,shareddata,NA

// read_unlock(&mylock) func call
E,e26,2,RMW,mylock,Rel

// write_lock(&mylock) func call
E,e27,2,RMW,mylock,Acq
E,e28,2,RMW,mylock,Rlx
E,e29,2,R,mylock,Rlx
E,e30,2,RMW,mylock,Rlx

E,e31,2,W,value,Rlx
E,e32,2,W,shareddata,NA

// write_unlock(&mylock) func call
E,e33,2,RMW,mylock,Rel

E,e34,2,R,value,Rlx



# Control Flow edges
CF e1 e2
CF e2 e3
CF e3 e4
CF e4 e5
CF e4 e20

CF e5 e5    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e5 at random

CF e5 e6    //if    (read_lock)
CF e5 e12   //else  (write_lock)

CF e6 e7
CF e6 e10   //without going into while loop

CF e7 e8

//not adding CF e8 e8 since it is just a sched_yield

CF e8 e9
CF e9 e7    //loop
CF e9 e10   //come out of loop

CF e10 e11

CF e11 e5
CF e11 e19

CF e12 e13
CF e12 e16  //without going into while loop

CF e13 e14

//not adding CF e14 e14 since it is just a sched_yield

CF e14 e15
CF e15 e13  //loop
CF e15 e16  //come out of loop

CF e16 e17
CF e17 e18

CF e18 e5
CF e18 e19

//Thread 2
CF e20 e20    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e20 at random

CF e20 e21    //if    (read_lock)
CF e20 e27   //else  (write_lock)

CF e21 e22
CF e21 e25   //without going into while loop

CF e22 e23

//not adding CF e23 e23 since it is just a sched_yield

CF e23 e24
CF e24 e22    //loop
CF e24 e25   //come out of loop

CF e25 e26

CF e26 e20
CF e26 e34

CF e27 e28
CF e27 e31  //without going into while loop

CF e28 e29

//not adding CF e29 e29 since it is just a sched_yield

CF e29 e30
CF e30 e28  //loop
CF e30 e31  //come out of loop

CF e31 e32
CF e32 e33

CF e33 e20
CF e33 e34
