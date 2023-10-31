// SPDX-License-Identifier: GPL-2.0-only
/// Remove naked cond_resched() statements
///
//# Remove cond_resched() statements when:
//#   - executing at the same control flow level as the previous or the
//#     next statement (this lets us avoid complicated conditionals in
//#     the neighbourhood.)
//#   - they are of the form "if (need_resched()) cond_resched()" which
//#     is always safe.
//#
//# Coccinelle generally takes care of comments in the immediate neighbourhood
//# but might need to handle other comments alluding to rescheduling.
//#
virtual patch
virtual context

@ r1 @
identifier r;
@@

(
 r = cond_resched();
|
-if (need_resched())
-	cond_resched();
)

@ r2 @
expression E;
statement S,T;
@@
(
 E;
|
 if (E) S
|
 if (E) S else T
|
)
-cond_resched();

@ r3 @
expression E;
statement S,T;
@@
-cond_resched();
(
 E;
|
 if (E) S
|
 if (E) S else T
)
