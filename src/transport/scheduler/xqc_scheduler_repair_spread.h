/**
 * repair-spread multipath scheduler: sources on the lowest-srtt path (minrtt),
 * repair packets round-robin over the other active paths, one per path.
 */
#ifndef _XQC_SCHEDULER_REPAIR_SPREAD_H_INCLUDED_
#define _XQC_SCHEDULER_REPAIR_SPREAD_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_repair_spread_scheduler_cb;

#endif /* _XQC_SCHEDULER_REPAIR_SPREAD_H_INCLUDED_ */
