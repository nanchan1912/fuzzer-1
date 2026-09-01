# Shared Locations
LOC flag0
LOC flag1
LOC turn
LOC var

# Event: ID TID  Kind  Loc  Mode
E,e1,0,W,flag0,NA
E,e2,0,W,flag1,NA
E,e3,0,W,turn,NA
E,e4,0,W,var,NA
E,e5,0,W,flag0,NA
E,e6,0,W,flag1,NA
E,e7,0,W,turn,NA
E,e8,1,W,flag0,Rlx
E,e9,1,R,flag1,Rlx
E,e10,1,R,turn,Rlx

E,e11,1,F,,Acq
E,e12,1,W,var,NA
E,e13,1,W,turn,Rlx
E,e14,1,F,,Rel
E,e15,1,W,flag0,Rlx

E,e16,1,W,flag0,Rlx
E,e17,1,R,turn,Rlx
E,e18,1,W,flag0,Rlx
E,e19,1,F,,SC

E,e20,2,W,flag1,Rlx
E,e21,2,F,,SC
E,e22,2,R,flag0,Rlx
E,e23,2,R,turn,Rlx

E,e24,2,F,,Acq
E,e25,2,W,var,NA
E,e26,2,W,turn,Rlx
E,e27,2,F,,Rel
E,e28,2,W,flag1,Rlx

E,e29,2,W,flag1,Rlx
E,e30,2,R,turn,Rlx
E,e31,2,W,flag1,Rlx
E,e32,2,F,,SC



# Control Flow edges


CF [e1] 0,W,flag0,NA --> [e2] 0,W,flag1,NA

CF [e2] 0,W,flag1,NA --> [e3] 0,W,turn,NA
CF [e3] 0,W,turn,NA --> [e4] 0,W,var,NA
CF [e4] 0,W,var,NA --> [e5] 0,W,flag0,NA
CF [e5] 0,W,flag0,NA --> [e6] 0,W,flag1,NA
CF [e6] 0,W,flag1,NA --> [e7] 0,W,turn,NA

CF [e7] 0,W,turn,NA --> [e8] 1,W,flag0,Rlx
CF [e7] 0,W,turn,NA --> [e20] 2,W,flag1,Rlx

//THREAD 1 (p0)
CF [e8] 1,W,flag0,Rlx --> [e9] 1,R,flag1,Rlx

CF [e9] 1,R,flag1,Rlx --> [e10] 1,R,turn,Rlx
CF [e9] 1,R,flag1,Rlx --> [e11] 1,F,,Acq

CF [e10] 1,R,turn,Rlx --> [e16] 1,W,flag0,Rlx
CF [e10] 1,R,turn,Rlx --> [e9] 1,R,flag1,Rlx

CF [e11] 1,F,,Acq --> [e12] 1,W,var,NA
CF [e12] 1,W,var,NA --> [e13] 1,W,turn,Rlx
CF [e13] 1,W,turn,Rlx --> [e14] 1,F,,Rel
CF [e14] 1,F,,Rel --> [e15] 1,W,flag0,Rlx

CF [e16] 1,W,flag0,Rlx --> [e17] 1,R,turn,Rlx
CF [e17] 1,R,turn,Rlx --> [e18] 1,W,flag0,Rlx
CF [e18] 1,W,flag0,Rlx --> [e19] 1,F,,SC
CF [e19] 1,F,,SC --> [e9] 1,R,flag1,Rlx


//THREAD 2 (p1)
CF [e20] 2,W,flag1,Rlx --> [e21] 2,F,,SC
CF [e21] 2,F,,SC --> [e22] 2,R,flag0,Rlx

CF [e22] 2,R,flag0,Rlx --> [e23] 2,R,turn,Rlx
CF [e22] 2,R,flag0,Rlx --> [e24] 2,F,,Acq

CF [e23] 2,R,turn,Rlx --> [e29] 2,W,flag1,Rlx
CF [e23] 2,R,turn,Rlx --> [e22] 2,R,flag0,Rlx

CF [e24] 2,F,,Acq --> [e25] 2,W,var,NA
CF [e25] 2,W,var,NA --> [e26] 2,W,turn,Rlx
CF [e26] 2,W,turn,Rlx --> [e27] 2,F,,Rel
CF [e27] 2,F,,Rel --> [e28] 2,W,flag1,Rlx

CF [e29] 2,W,flag1,Rlx --> [e30] 2,R,turn,Rlx

CF [e30] 2,R,turn,Rlx --> [e31] 2,W,flag1,Rlx
CF [e31] 2,W,flag1,Rlx --> [e32] 2,F,,SC
CF [e32] 2,F,,SC --> [e22] 2,R,flag0,Rlx
