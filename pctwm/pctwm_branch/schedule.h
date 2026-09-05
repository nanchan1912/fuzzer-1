/** @file schedule.h
 *	@brief Thread scheduler.
 */

#ifndef __SCHEDULE_H__
#define __SCHEDULE_H__

#include "mymemory.h"
#include "modeltypes.h"
#include "classlist.h"
#include "params.h"

typedef enum enabled_type {
	THREAD_DISABLED,
	THREAD_ENABLED,
	THREAD_SLEEP_SET
} enabled_type_t;

void enabled_type_to_string(enabled_type_t e, char *str);

/** @brief The Scheduler class performs the mechanics of Thread execution
 * scheduling. */
class Scheduler {
public:
	Scheduler();
	void register_engine(ModelExecution *execution);

	void add_thread(Thread *t);
	void remove_thread(Thread *t);
	void sleep(Thread *t);
	void wake(Thread *t);
	Thread * select_next_thread();
	void set_current_thread(Thread *t);
	Thread * get_current_thread() const;
	void print() const;
	enabled_type_t * get_enabled_array() const { return enabled; };
	void remove_sleep(Thread *t);
	void add_sleep(Thread *t);
	enabled_type_t get_enabled(const Thread *t) const;
	bool is_enabled(const Thread *t) const;
	bool is_enabled(thread_id_t tid) const;
	bool is_sleep_set(const Thread *t) const;
	bool is_sleep_set(thread_id_t tid) const;
	bool all_threads_sleeping() const;
	void set_scheduler_thread(thread_id_t tid);

	// related funcs

	void setParams(struct model_params * _params) {
		params = _params;
		setlowvec(params->bugdepth);
		//set_chg_pts(params->bugdepth, params->maxscheduler);
		set_chg_pts_byread(params->bugdepth, params->maxread);
		schelen_limit = 5 * params->maxscheduler;
		if(params->version == 1) {
			model_print("using pct version now. \n");
			pctactive();
		}
		else model_print("using c11tester original version now. \n");
		print_chg();
	}


	void setlowvec(int bugdepth){
		if(bugdepth > 1){
			lowvec.resize(bugdepth - 1,-1);
		}
		else lowvec.resize(1);
		
	}

	void set_chg_pts(int bugdepth, int maxscheduler){
		if(bugdepth <= 1){
			chg_pts.resize(1, rand() % maxscheduler);
		}
		else{
			chg_pts.resize(bugdepth - 1);
			for(int i = 0; i < bugdepth - 1; i++){
				int tmp = getRandom(maxscheduler); // [1, MAXSCHEDULER]
				while(chg_pts.find(tmp)){
					tmp = getRandom(maxscheduler);
				}
				chg_pts[i] = tmp;

			}
		}
		
	}

	//pctwm
	void set_chg_pts_byread(int bugdepth, int maxread){
		if(bugdepth <= 1){
			chg_pts.resize(1, rand() % maxread);
		}
		else{
			chg_pts.resize(bugdepth - 1);
			for(int i = 0; i < bugdepth - 1; i++){
				int tmp = getRandom(maxread); // [1, MAXSCHEDULER]
				while(chg_pts.find(tmp)){
					tmp = getRandom(maxread);
				}
				chg_pts[i] = tmp;

			}
		}
		
	}

	int getRandom(int range){
		int res = rand() % range;
		res = res < 1 ? 1 : res;
		return res;
	}


	void print_chg(){
		model_print("Change Priority Points:  ");
		for(uint64_t i = 0; i < chg_pts.size(); i++){
			model_print("[%u]: %d  ", i, chg_pts[i]);
		}
		model_print("\n");

	}


	void print_lowvec(){
		model_print("Low priority threads:  ");
		for(uint64_t i = 0; i < lowvec.size(); i++){
			model_print("[%u]: %d  ", i, lowvec[i]);
		}
		model_print("\n");

	}

	void incSchelen(){
		schelen++;
	}

	int getSchelen(){
		return schelen;
	}

	int find_chgidx(int schelen){
		int res = -1;
		for(uint i = 0; i < chg_pts.size(); i++){
			if(schelen == chg_pts[i]) res = i;
		}
		return res;
	}

	void highvec_addthread(Thread *t);

	void print_highvec(){
		model_print("high priority vector: ");
		for(int i = 0; i < highsize; i++){
			model_print("[%d] : %d", i, highvec[i]);
		}
		model_print("\n");
	}


	void print_avails(int* availthreads, int availnum);
	int find_highest(int* availthreads, int availnum);
	void movethread(int lowvec_idx);
	void pctactive(){
		usingpct = 1;
	}

	bool inhighvec(int threadid){
		for(int i = 0; i < highsize; i++){
			if(highvec[i] == threadid) return true;
		}
		return false;
	}


	SNAPSHOTALLOC
private:
	ModelExecution *execution;
	/** The list of available Threads that are not currently running */
	enabled_type_t *enabled;
	int enabled_len;
	int curr_thread_index;
	void set_enabled(Thread *t, enabled_type_t enabled_status);

	/** The currently-running Thread */
	Thread *current;

	//PCT
	struct model_params * params;

	SnapVector<int> lowvec;
	SnapVector<int> chg_pts;
	int schelen;

	SnapVector<int> highvec;
	int highsize;
	int schelen_limit;
	bool livelock;
	int usingpct;
};

#endif	/* __SCHEDULE_H__ */
