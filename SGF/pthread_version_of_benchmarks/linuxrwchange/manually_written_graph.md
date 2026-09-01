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
CF e4 e21

CF e6 e6    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e6 at random

CF e6 e7    //if    (read_lock)
CF e6 e13   //else  (write_lock)

CF e7 e8
CF e7 e11   //without going into while loop

CF e8 e9

//not adding CF e9 e9 since it is just a sched_yield

CF e9 e10
CF e10 e8    //loop
CF e10 e11   //come out of loop

CF e11 e12

CF e12 e6
CF e12 e5

CF e13 e14
CF e13 e17  //without going into while loop

CF e14 e15

//not adding CF e15 e15 since it is just a sched_yield

CF e15 e16
CF e16 e14  //loop
CF e16 e17  //come out of loop

CF e17 e18
CF e18 e19

CF e19 e6
CF e19 e5

//Thread 2
CF e21 e21    //loop LOOPNUM times - LOOPNUM determined randomly by mutator by either choosing this edge or other edge from e21 at random

CF e21 e22    //if    (read_lock)
CF e21 e28   //else  (write_lock)

CF e22 e23
CF e22 e26   //without going into while loop

CF e23 e24

//not adding CF e24 e24 since it is just a sched_yield

CF e24 e25
CF e25 e23    //loop
CF e25 e26   //come out of loop

CF e26 e27

CF e27 e21
CF e27 e20

CF e28 e29
CF e28 e32  //without going into while loop

CF e29 e30

//not adding CF e30 e30 since it is just a sched_yield

CF e30 e31
CF e31 e29  //loop
CF e31 e32  //come out of loop

CF e32 e33
CF e33 e34

CF e34 e21
CF e34 e20



//changes made: e19 -> e5, incremented all

// e34 -> e20