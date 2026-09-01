**Looking at inst:**    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
Exploring a call instruction
[CHECK CALL INST] Checking the inst:    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
--> Found a call inst in the bb: [   %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 ]
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Called function identified: _Znwm
Call site ID does not exist for the call instruction
# --> Should I care about this?


**Looking at inst:**    call void @_ZN16spinning_barrierC2Ej(ptr noundef nonnull align 4 dereferenceable(96) %call, i32 noundef 2) 
Exploring a call instruction
[CHECK CALL INST] Checking the inst:    call void @_ZN16spinning_barrierC2Ej(ptr noundef nonnull align 4 dereferenceable(96) %call, i32 noundef 2) 
--> Found a call inst in the bb: [   call void @_ZN16spinning_barrierC2Ej(ptr noundef nonnull align 4 dereferenceable(96) %call, i32 noundef 2) ]
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Called function identified: _ZN16spinning_barrierC2Ej
OLD CXT: [: ]
NEW CXT: [:8  ]
[DEBUG FUNC] Extracting instructions from _ZN16spinning_barrierC2Ej
cs_cxt of the func: [:8  ]
Prev shared inst:    store atomic i32 %0, ptr @value monotonic, align 4 
Context of Prev shared inst: [: ]
**Looking at inst:**    %this.addr = alloca ptr, align 8 
Exploring a non-call instruction
check_inst called for the inst:    %this.addr = alloca ptr, align 8 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
--> Neither shared, nor call
**Looking at inst:**    %n.addr = alloca i32, align 4 
Exploring a non-call instruction
check_inst called for the inst:    %n.addr = alloca i32, align 4 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
--> Neither shared, nor call
**Looking at inst:**    store ptr %this, ptr %this.addr, align 8 
Exploring a non-call instruction
check_inst called for the inst:    store ptr %this, ptr %this.addr, align 8 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store ptr %this, ptr %this.addr, align 8 
[DEBUG PTS TO] PAG node ID 345 points to node 346
[DEBUG] Shared variable instruction: MemObj : 346   %this.addr = alloca ptr, align 8 

SHARED LOC: this.addr
val is:    %this.addr = alloca ptr, align 8 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: this.addr
--> This is not a shared variable: this.addr
**Looking at inst:**    store i32 %n, ptr %n.addr, align 4 
Exploring a non-call instruction
check_inst called for the inst:    store i32 %n, ptr %n.addr, align 4 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store i32 %n, ptr %n.addr, align 4 
[DEBUG PTS TO] PAG node ID 347 points to node 348
[DEBUG] Shared variable instruction: MemObj : 348   %n.addr = alloca i32, align 4 

SHARED LOC: n.addr
val is:    %n.addr = alloca i32, align 4 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: n.addr
--> This is not a shared variable: n.addr
**Looking at inst:**    %this1 = load ptr, ptr %this.addr, align 8 
Exploring a non-call instruction
check_inst called for the inst:    %this1 = load ptr, ptr %this.addr, align 8 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    %this1 = load ptr, ptr %this.addr, align 8 
[DEBUG PTS TO] PAG node ID 345 points to node 346
[DEBUG] Shared variable instruction: MemObj : 346   %this.addr = alloca ptr, align 8 

SHARED LOC: this.addr
val is:    %this.addr = alloca ptr, align 8 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: this.addr
--> This is not a shared variable: this.addr
**Looking at inst:**    %LOOPNUM = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 0 
Exploring a non-call instruction
check_inst called for the inst:    %LOOPNUM = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 0 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
--> Neither shared, nor call
**Looking at inst:**    store i32 1, ptr %LOOPNUM, align 4 
Exploring a non-call instruction
check_inst called for the inst:    store i32 1, ptr %LOOPNUM, align 4 
prevInst:    store atomic i32 %0, ptr @value monotonic, align 4 
prevInst context: [: ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store i32 1, ptr %LOOPNUM, align 4 
[DEBUG PTS TO] PAG node ID 352 points to node 381
[DEBUG] Shared variable instruction: MemObj : 320   %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 

SHARED LOC: call
val is:    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: call
Writing shared inst [   store i32 1, ptr %LOOPNUM, align 4 ] to thread events
[DEBUG 2] location.size = 4
[DEBUG]Instruction:    store i32 1, ptr %LOOPNUM, align 4 
[DEBUG]Info: eventID: e4, TID: 0, W, loc: call, access_mode: NA
Wrote inst [   store i32 1, ptr %LOOPNUM, align 4 ] to thread events, prevInst: [   store atomic i32 %0, ptr @value monotonic, align 4 ]
prevInst has the evnt ID: e3
inst has the evnt ID: e4
[Creating CF Edge] from: [   store atomic i32 %0, ptr @value monotonic, align 4 ] --> to [   store i32 1, ptr %LOOPNUM, align 4 ]
setting prevInst to:    store i32 1, ptr %LOOPNUM, align 4 
Returning the prevInst from check_inst:    store i32 1, ptr %LOOPNUM, align 4 
Returning the prevInst_cxt from check_inst: prevInst_cxt: [:8  ]
**Looking at inst:**    %n_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 1 
Exploring a non-call instruction
check_inst called for the inst:    %n_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 1 
prevInst:    store i32 1, ptr %LOOPNUM, align 4 
prevInst context: [:8  ]
--> Neither shared, nor call
**Looking at inst:**    %0 = load i32, ptr %n.addr, align 4 
Exploring a non-call instruction
check_inst called for the inst:    %0 = load i32, ptr %n.addr, align 4 
prevInst:    store i32 1, ptr %LOOPNUM, align 4 
prevInst context: [:8  ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    %0 = load i32, ptr %n.addr, align 4 
[DEBUG PTS TO] PAG node ID 347 points to node 348
[DEBUG] Shared variable instruction: MemObj : 348   %n.addr = alloca i32, align 4 

SHARED LOC: n.addr
val is:    %n.addr = alloca i32, align 4 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: n.addr
--> This is not a shared variable: n.addr
**Looking at inst:**    store i32 %0, ptr %n_, align 4 
Exploring a non-call instruction
check_inst called for the inst:    store i32 %0, ptr %n_, align 4 
prevInst:    store i32 1, ptr %LOOPNUM, align 4 
prevInst context: [:8  ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store i32 %0, ptr %n_, align 4 
[DEBUG PTS TO] PAG node ID 354 points to node 382
[DEBUG] Shared variable instruction: MemObj : 320   %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 

SHARED LOC: call
val is:    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: call
Writing shared inst [   store i32 %0, ptr %n_, align 4 ] to thread events
[DEBUG 2] location.size = 4
[DEBUG]Instruction:    store i32 %0, ptr %n_, align 4 
[DEBUG]Info: eventID: e5, TID: 0, W, loc: call, access_mode: NA
Wrote inst [   store i32 %0, ptr %n_, align 4 ] to thread events, prevInst: [   store i32 1, ptr %LOOPNUM, align 4 ]
prevInst has the evnt ID: e4
inst has the evnt ID: e5
[Creating CF Edge] from: [   store i32 1, ptr %LOOPNUM, align 4 ] --> to [   store i32 %0, ptr %n_, align 4 ]
setting prevInst to:    store i32 %0, ptr %n_, align 4 
Returning the prevInst from check_inst:    store i32 %0, ptr %n_, align 4 
Returning the prevInst_cxt from check_inst: prevInst_cxt: [:8  ]
**Looking at inst:**    %nwait_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 3 
Exploring a non-call instruction
check_inst called for the inst:    %nwait_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 3 
prevInst:    store i32 %0, ptr %n_, align 4 
prevInst context: [:8  ]
--> Neither shared, nor call
**Looking at inst:**    store i32 0, ptr %nwait_, align 4 
Exploring a non-call instruction
check_inst called for the inst:    store i32 0, ptr %nwait_, align 4 
prevInst:    store i32 %0, ptr %n_, align 4 
prevInst context: [:8  ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store i32 0, ptr %nwait_, align 4 
[DEBUG PTS TO] PAG node ID 357 points to node 383
[DEBUG] Shared variable instruction: MemObj : 320   %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 

SHARED LOC: call
val is:    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: call
Writing shared inst [   store i32 0, ptr %nwait_, align 4 ] to thread events
[DEBUG 2] location.size = 4
[DEBUG]Instruction:    store i32 0, ptr %nwait_, align 4 
[DEBUG]Info: eventID: e6, TID: 0, W, loc: call, access_mode: NA
Wrote inst [   store i32 0, ptr %nwait_, align 4 ] to thread events, prevInst: [   store i32 %0, ptr %n_, align 4 ]
prevInst has the evnt ID: e5
inst has the evnt ID: e6
[Creating CF Edge] from: [   store i32 %0, ptr %n_, align 4 ] --> to [   store i32 0, ptr %nwait_, align 4 ]
setting prevInst to:    store i32 0, ptr %nwait_, align 4 
Returning the prevInst from check_inst:    store i32 0, ptr %nwait_, align 4 
Returning the prevInst_cxt from check_inst: prevInst_cxt: [:8  ]
**Looking at inst:**    %step_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 4 
Exploring a non-call instruction
check_inst called for the inst:    %step_ = getelementptr inbounds %class.spinning_barrier, ptr %this1, i32 0, i32 4 
prevInst:    store i32 0, ptr %nwait_, align 4 
prevInst context: [:8  ]
--> Neither shared, nor call
**Looking at inst:**    store i32 0, ptr %step_, align 4 
Exploring a non-call instruction
check_inst called for the inst:    store i32 0, ptr %step_, align 4 
prevInst:    store i32 0, ptr %nwait_, align 4 
prevInst context: [:8  ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store i32 0, ptr %step_, align 4 
[DEBUG PTS TO] PAG node ID 359 points to node 384
[DEBUG] Shared variable instruction: MemObj : 320   %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 

SHARED LOC: call
val is:    %call = call noalias noundef nonnull ptr @_Znwm(i64 noundef 96) #5 
llvm_func is null, llvm_val is not a function
[DEBUG 0] Load/Store location: call
Writing shared inst [   store i32 0, ptr %step_, align 4 ] to thread events
[DEBUG 2] location.size = 4
[DEBUG]Instruction:    store i32 0, ptr %step_, align 4 
[DEBUG]Info: eventID: e7, TID: 0, W, loc: call, access_mode: NA
Wrote inst [   store i32 0, ptr %step_, align 4 ] to thread events, prevInst: [   store i32 0, ptr %nwait_, align 4 ]
prevInst has the evnt ID: e6
inst has the evnt ID: e7
[Creating CF Edge] from: [   store i32 0, ptr %nwait_, align 4 ] --> to [   store i32 0, ptr %step_, align 4 ]
setting prevInst to:    store i32 0, ptr %step_, align 4 
Returning the prevInst from check_inst:    store i32 0, ptr %step_, align 4 
Returning the prevInst_cxt from check_inst: prevInst_cxt: [:8  ]
**Looking at inst:**    ret void 
Found a return instruction
[DEBUG FUNC] Finished extracting instructions and edges from the function: _ZN16spinning_barrierC2Ej
last shared insts found in the func: 
     store i32 0, ptr %step_, align 4 
Events returned from extract_insts_and_edges as last_inst: 
   store i32 0, ptr %step_, align 4 
Context of the last inst: [:8  ]
**Looking at inst:**    store ptr %call, ptr @barr, align 8 
Exploring a non-call instruction
check_inst called for the inst:    store ptr %call, ptr @barr, align 8 
prevInst:    store i32 0, ptr %step_, align 4 
prevInst context: [:8  ]
Atomic Ordering: NotAtomic
--> Load/Store/Fence/RMW
[DEBUG 0] Found a load/store instruction:    store ptr %call, ptr @barr, align 8 
[DEBUG 0] Load/Store location: barr
Writing shared inst [   store ptr %call, ptr @barr, align 8 ] to thread events
[DEBUG 2] location.size = 4
[DEBUG]Instruction:    store ptr %call, ptr @barr, align 8 
[DEBUG]Info: eventID: e8, TID: 0, W, loc: barr, access_mode: NA
Wrote inst [   store ptr %call, ptr @barr, align 8 ] to thread events, prevInst: [   store i32 0, ptr %step_, align 4 ]
prevInst has the evnt ID: e7
inst has the evnt ID: e8
[Creating CF Edge] from: [   store i32 0, ptr %step_, align 4 ] --> to [   store ptr %call, ptr @barr, align 8 ]
setting prevInst to:    store ptr %call, ptr @barr, align 8 
Returning the prevInst from check_inst:    store ptr %call, ptr @barr, align 8 
Returning the prevInst_cxt from check_inst: prevInst_cxt: [: ]
