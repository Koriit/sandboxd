#!/usr/bin/env python3
"""Gateway-owner uid invariant: the contract, and a perishable check derived from it.

WHAT THIS ENFORCES.  One decision runs through `sandboxd/sandboxd/src/main.rs`
-- *whose gateway is this?* -- and three families of function touch it.  Each is
defined by the CLASS OF UID IT MAY RECEIVE (F1/F2/F3 below).  Handing the wrong
class to the wrong family is SILENT in the configuration that ships today,
because while per-operator gateways are off the collapse `gateway_owner_uid()` is
the identity on the daemon's own uid.  The defect therefore cannot appear until
the switch is ON -- the configuration this work exists to enable -- so no test on
the current tree exercises the configuration in which it fires.  That is the gap
this checker covers, and it is why the clauses can be vacuous (zero true
positives) and still be worth running.

WHAT IT READS.  `sandboxd/sandboxd/src/main.rs` for C0-C7,
`sandboxd/sandbox-core/src/gateway_lima.rs` for the C4 carve-out's premise check,
and `sandboxd/sandbox-agent/src/protocol.rs` for C8.  Nothing else -- so it has
nothing to say about any other file, however relevant.

C8 IS NOT PART OF THE UID CONTRACT and does not pretend to be.  It rides here
because it is a standing constraint with the same failure mode as the ones above
-- correct today, silently violated by a future edit, no test that fires -- and
because the alternative was leaving it as a count with no baseline to compare
against.  Its own block states what it does and does not cover; read that before
reading a green from it as a claim about the wire.

    scripts/check-gateway-owner-uid-invariant.py                 # the working tree
    scripts/check-gateway-owner-uid-invariant.py --self-test     # prove it can go RED
    scripts/check-gateway-owner-uid-invariant.py --rev 7b3511d   # a committed revision
    scripts/check-gateway-owner-uid-invariant.py --tree <dir>    # an extracted workspace

Exit 0 = no violations.  Exit 1 = violations, or a scope failure that makes any
verdict meaningless (see C0).

A CLEAN RUN ALONE IS NOT A RESULT.  A correct tree and a checker that measured
nothing both print zero violations, and nothing in that number tells them apart.
Two things separate them, and both must be read:

  * the SCOPE and DENOMINATOR lines every run prints -- how much of the file was
    scanned, how many functions the selector matched against how many exist, how
    many registered route handlers it covers (the independent landmark), and
    per-clause, how many sites each clause reached a DECISION on.  A clause whose
    denominator is zero decided nothing; that is an absent result wearing a clean
    one, and the report says so rather than hiding it.
  * `--self-test`, which injects a real contract violation for every clause into
    a throwaway copy and requires each to go RED.  Run it on the SAME revision as
    the clean run.  A green run whose self-test was not also run on that revision
    certifies nothing.

WHY THE DEFAULT IS THE WORKING TREE.  This file began as an audit of a claim
about one particular commit, and for that job anchoring at a fixed revision is
right: the question was whether THAT tree held the invariant, and a moving target
would have answered a different question each run.  As a gate the same default is
wrong -- a gate must read whatever is being changed now, or it certifies a commit
nobody is editing while the working tree drifts freely past it.  So the default is
the working tree, uncommitted edits included, and `--rev` keeps the anchored
behaviour for re-auditing a specific commit.  Every run prints which of the two it
read, because a green result whose provenance is unstated is the same
unfalsifiable shape as a numerator without a denominator.

`--self-test` deliberately writes broken code into the tree it runs on, so it
always runs against a throwaway copy -- a `git archive` extraction for `--rev`, a
scratch copy of the sources for the working-tree default -- and refuses outright
if pointed at the repository itself.

READ THE CONTRACT FIRST; THE PATTERNS BELOW ARE AN IMPLEMENTATION DETAIL.

The durable artifact is the three-family contract, stated in terms of *what uid
each family may receive*.  It has outlived every pattern that implemented it:
each refactor of this code so far -- a rename, then an extraction, then the
deletion of the daemon-wide route -- broke some pattern below or some anchor in
the self-test, while the contract itself needed no amendment.  Expect the next
one to do the same, and fix the pattern rather than the contract:

  F1  operator-facing gateway entry points.  RECEIVE: an operator uid -- the uid
      of whoever's request is being served.  They collapse to the gateway owner
      internally, so callers must not pre-collapse.  MUST NOT RECEIVE: the
      daemon's own uid, an already-collapsed owner uid, or a literal.
      Names today: gateway_owner_uid, docker_route_for_operator,
      gateway_lima_manager_for_operator, resolve_docker_route.

  F2  the per-session Lima registry.  RECEIVES: a RAW operator uid, always.
      Session VMs belong to their operator whether or not per-operator gateways
      are switched on, so there is no configuration in which collapsing is
      right.  MUST NOT RECEIVE: gateway_owner_uid(...) of anything.
      Names today: lima_runtime.manager_for, lima_runtime.registry().get_or_create.

  F3  owner-keyed sinks.  RECEIVE: an ALREADY-COLLAPSED owner uid.  Passing a
      raw operator uid here aims at the wrong gateway the moment the switch is
      on.  Their *outputs* are owner-scoped and must not be handed to code
      serving a caller.
      Names today: the gateway_docker_route factory field, the
      gateway_lima_managers registry; and the two daemon-wide singletons built
      from them at startup, state.docker and state.gateway_lima_manager.

A FOURTH NAME WILL LAND -- PLAN FOR IT, DO NOT PATCH AROUND IT.
This family has gained a name twice in one week: `foo` -> `foo_for_operator`
(rename), then a free function extracted out of an accessor body (extraction).
Both are the codebase's normal way of changing this code, so assume a fifth.
When a name appears or moves, the maintainer's job is:

  1. Decide which family it is in FROM THE CONTRACT -- ask what uid it may
     receive, not what it is called or where it is called from.
  2. Add it to that family's tuple below WITH THE REASON IT BELONGS, in a
     comment at the entry.  An unexplained entry is indistinguishable from an
     allowlist bolted on to silence a hit, and an allowlist is exactly how the
     prefix defect this file exists because of would have been entrenched.
  3. Re-run --self-test.  A clause whose RED demonstration no longer fires has
     rotted; a clause that now fires on correct code has inverted.  Both are
     expected outcomes of a rename, and both are why --self-test gates.

WHAT EACH CLAUSE ACTUALLY MEASURES -- STATED PLAINLY.
C3 and C4 are contract clauses: each goes RED on a call that passes the WRONG
UID CLASS with every identifier spelled correctly and current.  C1 and C2 are
not.  They detect one specific contract violation -- an F3 output reaching
caller-serving code -- but they detect it BY NAME, so they can only be shown red
by a spelling.  By the standard "if a clause can only be shown red by a spelling
violation, it is measuring spelling", C1 and C2 measure spelling.  They are kept
as cheap backstops on the two known singleton fields, not mistaken for coverage
of the class; C4 is what covers the class.  The self-test demonstrates this
directly: its C4 injection is a real defect that C1 and C2 stay GREEN on.

C8 is a third kind again, and the weakest of the three: a fixed-name denylist
compared against a recorded count.  It cannot be shown red by a contract
violation, only by a KNOWN SPELLING appearing more often than it did.  A new
free-form field under an unwatched name passes it silently.  It is a regression
guard on shapes that have gone wrong before, not a check of the property.

NO SHELL SEARCH TOOLS ARE USED HERE, DELIBERATELY.  `grep`, `rg` and `find` can
be shell *functions* rather than the programs they name, and a function silently
becomes a different program -- or vanishes -- inside a nested shell, which a
script file always is.  Everything below is pure Python `re` over a snapshot of
the sources.  Nothing here parses Rust: these are regexes over text, which is why
every clause carries a denominator and a RED demonstration rather than trust.
"""
import argparse
import collections
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import pathlib

# Set from --repo-root in __main__; module-level so `extract_rev` and the
# working-tree snapshot can both reach it.
REPO = None

FN_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")

# ---------------------------------------------------------------------------
# "Request-serving" -- a function that can name WHOSE request this is.
#
# This is the precondition for C1, C2 and C4, and it is where this file's
# nastiest defect lived.  The first spelling was `\boperator:\s*\w*Operator`,
# which does not match `Extension(operator): Extension<OperatorIdentity>` -- the
# axum extractor form, i.e. every actual HTTP handler.  It matched only plain
# helpers like `create_session_macos_lima(.., operator: OperatorIdentity, ..)`.
# MEASURED at 7b3511d: it selected 10 functions where the correct definition
# selects 27; the 18 it missed are create_session, stop_session, remove_session,
# get_session, session_health, get_proxy, diagnostics_handler, list_sessions,
# start_session, exec_in_session, get_ssh_config, rebuild_image,
# base_image_status, {get,update,clear}_policy_handler and the two
# workspace-lock handlers.  So the clauses' scope was close to the INVERSE of
# what its own comment claimed.
#
# That failure was silent: C1 and C2 reported 0 violations, which reads as
# reassurance.  Re-measured under the corrected definition they are still 0 at
# both 70a55f6 and 7b3511d -- the conclusion survived, the evidence for it did
# not.  Anyone re-deriving this must re-measure rather than inherit the number:
# every count in this file is dated to the revision it was taken at, and a
# number without a revision beside it is not evidence about your tree.
#
# Anchoring on the TYPE (`OperatorIdentity`) rather than the binding is what
# makes both spellings match, and it is also the more honest anchor: the type is
# the thing that carries caller identity.
#
# `owner_uid: u32` is deliberately NOT here.  An owner uid is post-collapse and,
# with the switch off, is the daemon's -- a function holding one cannot name a
# caller.  Including it would wrongly mark cleanup_lite_stage_dir as serving.
CALLER_PARAM = re.compile(
    r"\bOperatorIdentity\b|\b(?:operator_uid|op_uid)\s*:\s*u32\b")

# --- F1: operator-facing gateway entry points -------------------------------
# gateway_owner_uid                  -- the collapse itself; its argument IS the
#                                       operator uid by definition.
# docker_route_for_operator          -- accessor; collapses, then hits F3.
# gateway_lima_manager_for_operator  -- accessor; collapses, then hits F3.
# resolve_docker_route               -- BELONGS BECAUSE it is the accessor's
#                                       whole body, extracted so the collapse
#                                       could be tested without an AppState.  It
#                                       takes the factory as a parameter and the
#                                       operator uid beside it, and applies the
#                                       same collapse; by the contract question
#                                       ("what uid may it receive?") it is F1,
#                                       not a new family.  This is the third
#                                       name; see the header.
F1_NAMES = ("gateway_owner_uid", "docker_route_for_operator",
            "gateway_lima_manager_for_operator", "resolve_docker_route")
F1_CALL = re.compile(r"\b(" + "|".join(F1_NAMES) + r")\s*\(")

# A uid that is NOT the caller's.  These are what C4 forbids reaching F1 from
# inside a request-serving function.
NON_CALLER_UID = re.compile(
    r"\bdaemon_uid\b|\bUid::current\s*\(\)|^\s*\d+\s*(?:u32)?\s*$")

# Every `|` alternative above, separately, so the per-clause census can report
# which ones have actually fired.  An alternative contributing zero is the C3
# lesson waiting to repeat: it is either dead (wrong spelling) or guarding a
# case this tree does not contain, and those two look identical in a green run.
# Both of the non-`daemon_uid` alternatives were at zero when this census was
# first taken; the self-test now injects each one so "never fires here" is
# distinguishable from "cannot fire at all".
NON_CALLER_UID_ALTS = (
    ("daemon_uid", re.compile(r"\bdaemon_uid\b")),
    ("Uid::current()", re.compile(r"\bUid::current\s*\(\)")),
    ("bare literal", re.compile(r"^\s*\d+\s*(?:u32)?\s*$")),
)

# --- The one carve-out to C4, stated as a contract rule rather than a list ----
#
# A request-serving function MAY collapse the daemon's own uid, but only to ask
# a HOST-SCOPED question -- a fact about the daemon's Lima install that is the
# same number for every caller.  It may not use the resulting owner-scoped
# handle for anything else: not a route, not a session, not a lifecycle call.
#
# WHY THIS IS A RULE AND NOT AN ALLOWLIST.  A line-number or function-name
# allowlist would say "this site is fine" and carry no reason, so the next
# daemon-uid site gets appended to it by whoever is trying to get the check
# green -- which is precisely how the prefix defect that this file exists
# because of would have been entrenched.  This predicate instead says what makes
# such a site legitimate, so a site that stops satisfying it starts failing:
# rebind the handle to anything beyond a host-scoped read and C4 fires again.
#
# The site this describes today is `diagnostics_handler` asking for
# `lima_version`.  What licenses that is NOT the function's own doc-comment
# about Doctor wanting a host-wide answer -- in-tree prose has no validator, and
# citing it only moves the unverified claim one hop.  It is the PREMISE check
# below, which re-derives operator-invariance from the code on every run.
#
# ADMISSION RULE -- read this before adding a member.  A green premise check is
# NECESSARY AND NOT SUFFICIENT.  What it verifies is a PROXY -- zero `self`
# dereferences -- for the property that actually matters, which is that the
# answer cannot differ between two operators.  The proxy is sound in one
# direction only: a method touching no per-operator state cannot vary by
# operator, but a method can vary through the PROCESS it runs in without ever
# mentioning `self`.  With one member that gap is coverable by reading the
# method.  It opens at the SECOND, where the checker goes green and the green
# is read as an admission decision it was never able to make.
#
# So admitting a member takes a STATED ARGUMENT for operator-invariance, not a
# green run.  The argument for `lima_version` today -- the thing to re-examine,
# rather than the conclusion it supports -- is that ONE daemon process per host
# serves every operator, so the ambient environment `limactl --version`
# resolves against (PATH, environment, cwd) belongs to that single process and
# is operator-invariant by construction.  A reader given the reason can see it
# break; a reader given only the conclusion cannot.  Two things would end it
# while leaving the `self`-dereference count at zero and this checker green:
# per-operator daemon processes, and any query resolving its binary or its
# config through an owner's LIMA_HOME.
HOST_SCOPED_QUERIES = {"lima_version"}
BINDING_RE = re.compile(r"let\s+(?:mut\s+)?([A-Za-z0-9_]+)\s*=(?![=])")

# --- F2: the per-session Lima registry --------------------------------------
# Two spellings, and the second one is a lesson.  The previous version of this
# clause was `(?:\.manager_for|lima_registry\s*\.\s*get_or_create)\s*\(`.  The
# `lima_registry.get_or_create` alternative MATCHES NOTHING at either revision
# -- the real spelling is `lima_runtime.registry().get_or_create(...)` -- so
# half of C3 was dead and the 2 sites it was meant to cover were unchecked, in
# silence.  Both spellings are listed now; a third will need adding.
F2_SINK = re.compile(r"\.manager_for\s*\(|registry\s*\(\)\s*\.\s*get_or_create\s*\(")
COLLAPSE_CALL = re.compile(r"^(?:sandbox_core::)?gateway_owner_uid\s*\(")

# --- F3: owner-keyed singletons whose outputs must not serve a caller -------
#
# C1 and C2 are NAME-ANCHORED backstops.  They ask "is this daemon-built thing
# NAMED inside a function that has a caller", not "does this value reach a
# caller".  That is a deliberate limit with a known evasion: route the read
# through a helper and the name never appears in the handler.  The tree does
# exactly this today -- `runtime_for(&state, BackendKind::Container)` reaches the
# same daemon-built runtime from ~30 handler sites without spelling its name.
# Following a value through a helper is what C4 (argument class) and C6 (body)
# are for.  Do not try to make C1 do it.  Make C1 loud about the direct reads
# and state the limit, which is what this paragraph is.
#
# C1'S SUBJECT CHANGED, and the reason matters more than the change.  It used to
# be `state.docker`, the daemon-wide Docker route hung off shared state.  That
# field was deleted -- correctly: a route sitting in shared state names no owner,
# so a handler reaching for it would compile whether or not it had been
# converted.  C1 then went silently vacuous: the regex matched nothing, the
# denominator printed 0, and the run still exited 0.
#
# The question that repaired it was NOT "is C1's assertion still true" -- it was,
# trivially and uselessly.  It was "what REGION did C1 guard, and is that region
# still occupied".  C1 guarded *a daemon-built Docker route reaching a
# caller-serving function*.  Deleting the field removed one SPELLING of that, not
# the region.  The daemon's own route is still built at startup
# (`gateway_docker_route(daemon_uid)`) and still handed to two long-lived
# objects -- the container runtime and the gateway Lima manager -- and both are
# still reachable while serving a caller.  C2 already watches the second.  C1
# now watches the first.
#
# `state.runtimes` is in C1's scope as a second name for the same object: it is
# the dispatch table holding that one `Arc<ContainerRuntime>`, so a handler
# reaching the table directly is the same defect in different words.
#
# WHY NOT C5.  C5 checks the uid handed to an F3 FACTORY -- that
# `gateway_docker_route(..)` and `gateway_lima_managers.get_or_create(..)`
# receive an already-collapsed owner.  It says nothing about what happens to the
# route afterwards, and the startup call it does see is the legitimate one.  The
# route travelling INSIDE `ContainerRuntime` to a handler is invisible to it.
# The two clauses do not overlap here.
#
# EXPECT C1 TO BE RED ON A TREE WHERE THIS IS UNFINISHED.  Both
# `state.container_runtime` reads sit in create-session handlers and neither is
# converted; the conversion has no compile-time tripwire, because the route lives
# inside the object and a half-conversion behaves identically while per-operator
# gateways are off.  A red C1 there is a true finding about outstanding work, not
# a checker defect, and there is deliberately nowhere to put it -- this file has
# no accepted-violations list and must not grow one.
#
# TO CHECK C1 IS NOT MERELY OVER-BROAD, do not read it -- run it.  Extract the
# workspace (`git archive HEAD sandboxd | tar -x -C <dir>`; do NOT `cp -R` the
# workspace, `target/` makes that take minutes), rewrite the two reads as an
# owner-named accessor, and re-run with `--tree <dir>`.  The default run must go
# GREEN while `--self-test` still PASSES.  Green-on-converted plus red-on-
# unconverted is the pair; either half alone is consistent with a dead clause.
# That pair also puts `alt C1/state.container_runtime` at zero and prints it as
# UNEXPLAINED, which is correct and is the point: whoever does the real
# conversion should have to look at that line and say whether the spelling went
# away on purpose.
#
# ---------------------------------------------------------------------------
# A KNOWN GAP, NAMED RATHER THAN FIXED.  C1 counts a match unconditionally but
# only RAISES when the match's enclosing function is in the serving set, and
# that set is a ONE-LEVEL SIGNATURE TEST (`CALLER_PARAM`: an `OperatorIdentity`
# parameter, or `operator_uid`/`op_uid: u32`).  Nothing here walks the call
# graph.  So an F3 output read ONE HOP below a serving handler is counted and
# not reported, and because the parent counter stays non-zero, the vacuity
# check that catches a fully-collapsed clause does not fire either.
#
# This is not hypothetical and it is not benign.  Measured on the tree this was
# written against: 31 serving functions against 107 non-serving ones in the
# scanned region, of which 44 are called by name from inside a serving function
# (an upper bound -- name matching has false positives such as `Default::
# default`; `apply_policy` was verified by hand).  Demonstrated by construction:
# convert both real reads, then put a single `state.container_runtime` inside
# `apply_policy` -- which takes `caller_username: &str` AND `state: &AppState`,
# and is called from `create_session`, `create_session_macos_lite` and
# `update_policy` -- and the run reports PASS, exit 0, with
# `alt C1/state.container_runtime` at 1.
#
# THE REPORT DOES NOT MERELY MISS IT, IT CERTIFIES THE OPPOSITE.  With the
# parent counter non-zero, `C1 in a serving fn` at zero prints its
# DENOM_ZERO_OK reason -- "converted, IF `C1` above is non-zero" -- whose
# condition is satisfied.  So a tree with an unconverted read one hop down from
# three serving handlers prints an affirmative statement that the conversion is
# done.  That is worse than silence and is the reason this paragraph exists.
#
# WHY IT IS NOT FIXED HERE.  The obvious repair is to pin the expected count,
# and that was ruled against: C1 measures a set that is SUPPOSED TO DRAIN TO
# ZERO, so a pin would be wrong at every increment of correct work and would be
# edited on each conversion -- a check whose numbers are routinely edited to
# make it pass has trained its own bypass.  The real repair is call-graph
# reachability rather than a signature test, which is a different instrument
# from this one.  Until then: C1 is a backstop on reads that DIRECTLY serve a
# caller, and a green C1 says nothing about reads one hop below one.
C1_ALTS = (
    ("state.container_runtime", re.compile(r"\bstate\s*\.\s*container_runtime\b")),
    ("state.runtimes", re.compile(r"\bstate\s*\.\s*runtimes\b")),
)
C2_ALTS = (
    ("state.gateway_lima_manager",
     re.compile(r"\bstate\s*\.\s*gateway_lima_manager\b")),
)
FIELD_CLAUSES = [
    ("C1", re.compile(r"\bstate\s*\.\s*(?:container_runtime|runtimes)\b"),
     "daemon-built container runtime", C1_ALTS),
    ("C2", re.compile(r"\bstate\s*\.\s*gateway_lima_manager\b"),
     "singleton gateway Lima manager", C2_ALTS),
]
# The `\b` is load-bearing, not stylistic.  Spelled as bare literals, as an
# earlier draft was, `state.docker` matched `state.docker_route_for_operator`
# and `state.gateway_lima_manager` matches `state.gateway_lima_manager_for_
# operator`: the rule then flags every correctly-converted site and nothing
# else.  MEASURED at 70a55f6: literal spelling 4 + 4 "violations", all of them
# correct code; `\b` spelling 0 + 0.  Both singular fields do exist -- AppState
# declares `gateway_lima_manager` and `gateway_lima_managers` side by side -- so
# `\b` separates two real things rather than suppressing a phantom.
#
# The `\s*` around the `.` is load-bearing for a DIFFERENT reason, and it is why
# these two clauses scan the whole file text instead of line by line as they used
# to.  rustfmt splits a chained field access across lines, so the real text at
# both container-runtime sites is:
#
#     state
#         .container_runtime
#         .register_session(session_id, container_network);
#
# A line-anchored scan sees `state` on one line and `.container_runtime` on the
# next and matches NEITHER.  MEASURED on the tree this was written against: the
# line-anchored form finds 0 of the 2 `state.container_runtime` sites and 1 of
# the 2 `state.runtimes` sites -- it would have reported C1 vacuous a second
# time, for a completely different reason, one line after the comment explaining
# the first.


# --- F3 sinks, and what reaching one obliges ---------------------------------
#
# C5 and C6 were PORTED from an earlier, now-retired audit instrument that is
# not in this repository -- which is the reason they are spelled out here at
# length rather than cited.  Retiring a check is a PERMISSIVE change: it can
# only ever remove protection, so the properties the retired check held that
# C1-C4 did not were measured by injection BEFORE it was removed, never after.
# All three defects below were GREEN under C1-C4 alone:
#
#   (state.gateway_docker_route)(operator.uid)  in a serving fn      -> GREEN
#   state.gateway_lima_managers.get_or_create(operator.uid)          -> GREEN
#   the collapse deleted from resolve_docker_route's body            -> GREEN
#
# The third is the worst defect this file can describe: every call site still
# reads correctly, every name is right, and every operator silently gets the
# daemon's gateway.  C4 cannot see it because C4 inspects arguments, and the
# argument is still `operator_uid`.
#
# NOT SPELLED AS CONTAINMENT-BY-APPROVED-FUNCTION-LIST, deliberately.  The
# retired check asked "is this sink named outside an approved set of
# functions", with the set frozen as a literal.  That set could not contain a
# function that did not exist when it was written -- so it flags correct code
# after any extraction, and a check that flags correct code trains people to
# ignore it.  MEASURED at 7b3511d: the frozen spelling reports 2 violations
# (`cleanup_lite_stage_dir`, `diagnostics_handler`), both correct.  C5 asks the
# contract question instead -- what uid class reaches the sink -- which needs no
# list and does not rot when a function is added.
F3_SINK_CALL = re.compile(
    r"\bgateway_lima_managers\b\s*\.?\s*(?:\n\s*)?\.?\s*get_or_create\s*\(|"
    r"\bgateway_docker_route\s*\)?\s*\(")

# --- the THIRD F3 sink: the gateway-recovery latch ---------------------------
#
# C7 is the second thing ported before a retirement, and it came from asking
# what the retired "recovery" pins were standing in front of rather than what
# they literally asserted.  `GatewayRecoveryLatches` is a plain
# `HashMap<u32, Arc<AtomicBool>>` (sandbox-core/src/gateway_recovery.rs) --
# neither `for_owner` nor `is_recovering` collapses, so by the contract's own
# definition it is an owner-keyed F3 sink, the third one, and C5 knew of two.
#
# MEASURED at 7b3511d, both GREEN under C1-C6 before this clause existed:
#   state.gateway_recovering.for_owner(operator.uid)      in a serving fn
#   state.gateway_recovering.is_recovering(operator.uid)  in a serving fn
#
# The failure it describes is a silent one in the worst way: writer and reader
# key the same map under two different uids, so the latch is simply never
# observed, the monitor never skips a session being recovered, and nothing
# errors -- recovery just races.  Both sites are correct at 7b3511d (the writer
# takes `shard.owner_uid`, built once at the single `GatewayOwnership::Shared`
# construction from `gateway_owner_uid(state.daemon_uid)`, which is the exact
# expression the reader polls under).  Correct and unchecked is the state this
# file exists to end.
#
# The `<binding>.owner_uid` acceptance is EARNED, like C5's: it holds only
# while every `GatewayOwnership::Shared` is collapsed.  And the coupling below
# is quoted from recover_gateway_lima's own doc comment -- `PerOperator` "is
# therefore not a one-line switch-over: it would produce a shard per owner
# while `recover_one_gateway` still drives the single
# `state.gateway_lima_manager`, force-stopping and restarting one VM once per
# shard and tearing down the sessions the previous shard had just recovered."
# So PerOperator is not flagged as wrong -- it is the target configuration --
# but it withdraws the earned acceptance and requires that the singleton drive
# in `recover_one_gateway` be gone in the same change.
LATCH_SINK = re.compile(
    r"\bgateway_recovering\s*\.\s*(?:for_owner|is_recovering)\s*\(")
OWNERSHIP_SHARED = re.compile(r"\bGatewayOwnership::Shared\s*\(")
OWNERSHIP_PEROP = re.compile(r"\bGatewayOwnership::PerOperator\s*\(")
OWNER_FIELD = re.compile(r"^[A-Za-z0-9_]+\.owner_uid$")
SINGLETON_DRIVE = re.compile(r"\bstate\.gateway_lima_manager\b")
RECOVERY_DRIVER = "recover_one_gateway"


def extract_rev(rev):
    """A committed revision, extracted to a scratch dir. Never the repo itself."""
    root = pathlib.Path(tempfile.mkdtemp(prefix=f"gw-owner-{rev}-"))
    tar = root / "t.tar"
    with open(tar, "wb") as fh:
        subprocess.run(["git", "archive", rev], cwd=REPO, stdout=fh, check=True)
    with tarfile.open(tar) as t:
        t.extractall(root)
    tar.unlink()
    return root


def snapshot_worktree():
    """The working tree -- uncommitted edits included -- copied to a scratch dir.

    A COPY, not the repository.  `--self-test` writes deliberately-broken code
    into whatever root it is handed, and the working tree is the one root where
    that would destroy real work.  Copying is also what makes the default
    honest: the clean run and the self-test then read the same bytes, which is
    the pairing the header requires.

    Enumerated through `git ls-files -c -o --exclude-standard`, so it carries
    tracked files *as they stand on disk* plus new untracked ones, and inherits
    .gitignore -- which is what keeps `sandboxd/target/` out.  Only `.rs` files
    are copied: this checker reads Rust sources and nothing else.
    """
    root = pathlib.Path(tempfile.mkdtemp(prefix="gw-owner-worktree-"))
    listed = subprocess.run(
        ["git", "ls-files", "-c", "-o", "--exclude-standard", "--", "sandboxd"],
        cwd=REPO, capture_output=True, text=True, check=True).stdout.split("\n")
    copied = 0
    for rel in listed:
        if not rel.endswith(".rs"):
            continue
        src = pathlib.Path(REPO) / rel
        if not src.is_file():
            continue  # tracked but deleted on disk
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        copied += 1
    return root, copied


def worktree_provenance():
    """What the working-tree snapshot actually read, stated on every run.

    A gate that does not say which bytes it graded is unfalsifiable in the same
    way a violation count without a denominator is: `PASS` looks identical
    whether it read your edits or a commit you have long since moved past.
    """
    def git(*a):
        return subprocess.run(["git", *a], cwd=REPO, capture_output=True,
                              text=True, check=True).stdout
    head = git("rev-parse", "--short", "HEAD").strip()
    # `--porcelain` lines are two status characters, a space, then the path, so
    # the path begins at index 3.  Do NOT strip the whole output first: that
    # eats the leading status space on the FIRST line only, chopping one
    # character off one path and leaving every other line correct -- a report
    # that is wrong in a way a single-file check would never show.
    dirty = [l[3:] for l in git("status", "--porcelain", "--", "sandboxd")
             .split("\n") if l.strip()]
    return head, dirty


def refuse_if_inside_repo(root):
    """`--self-test` must never be able to write broken code into the repo.

    The clean run only reads, but the self-test mutates its root in place and
    restores it afterwards -- and an interrupted restore leaves the damage
    behind.  Every supported source is a scratch copy, so this can only trip via
    `--tree`; it is asserted rather than trusted because the cost of being wrong
    once is somebody's uncommitted work.
    """
    root = root.resolve()
    repo = pathlib.Path(REPO).resolve()
    if root == repo or repo in root.parents or root in repo.parents:
        sys.exit(
            f"refusing --self-test: it writes broken code into its root, and "
            f"{root} overlaps the repository at {repo}.\n"
            f"Use the default (a working-tree copy), --rev, or a --tree outside "
            f"the repository.")


def fn_spans(lines):
    """{fn: [(start,end)]}, 1-based inclusive, by brace balancing."""
    spans = {}
    for i, l in enumerate(lines, 1):
        mo = FN_RE.match(l)
        if not mo:
            continue
        depth, seen, end = 0, False, None
        for j in range(i, len(lines) + 1):
            for ch in re.sub(r"//.*|\"(?:\\.|[^\"])*\"", "", lines[j - 1]):
                if ch == "{":
                    depth, seen = depth + 1, True
                elif ch == "}":
                    depth -= 1
            if seen and depth <= 0:
                end = j
                break
            if j - i > 4000:
                break
        spans.setdefault(mo.group(1), []).append((i, end if end else i))
    return spans


def signature_of(lines, a, b):
    head = []
    for j in range(a, min(b, a + 24) + 1):
        head.append(lines[j - 1])
        if "{" in lines[j - 1]:
            break
    h = "\n".join(head)
    return h[:h.find("{")] if h.find("{") > 0 else h


def enclosing_fn(spans, lineno):
    best = None
    for name, ranges in spans.items():
        for a, b in ranges:
            if a <= lineno <= b and (best is None or (b - a) < best[0]):
                best = (b - a, name)
    return best[1] if best else None


def commentish(s):
    """Is this line commented out?

    Lifted to module scope when C8 arrived and needed it against a second
    file.  It was a closure inside the main scan for as long as there was only
    one caller; two callers with two copies is how the daemon's scan and the
    wire scan would come to disagree about what counts as commented, silently
    and in the permissive direction.
    """
    return s.strip().startswith(("//", "*", "///"))


def serving_fns(lines, spans):
    out = set()
    for fn, ranges in spans.items():
        for a, b in ranges:
            if CALLER_PARAM.search(signature_of(lines, a, b)):
                out.add(fn)
    return out


def blind_region(lines, spans, served, tstart):
    """How many functions sit OUTSIDE C1/C2's reach but one call inside it.

    C1/C2 raise only when the enclosing function is in `served`, and `served`
    is a ONE-LEVEL SIGNATURE TEST.  An F3 output read one hop below a serving
    handler is therefore counted and never reported.  This counts the
    non-serving functions in the scanned region that are called BY NAME from
    inside a serving one -- the size of that unreachable region.

    THIS IS A SCOPE FIGURE, NOT A BASELINE.  Nothing breaks when it moves and
    it gates nothing, so it cannot be edited to make anything pass.  It exists
    so that a zero in `C1 in a serving fn` is read as "0 raised, over a region
    this size that the clause cannot see" instead of as "0 present".

    It is an UPPER BOUND and known to over-count: name matching cannot tell a
    call to a local `fn default` from `Default::default()`, and it resolves no
    methods, traits or shadowing.  An exact figure needs the call-graph
    reachability this file deliberately does not implement -- see the gap
    paragraph on C1.  Over-counting is the right direction for a scope figure:
    it must not understate what the clause is blind to.
    """
    bodies = "\n".join("\n".join(lines[a - 1:b])
                       for fn in served for a, b in spans.get(fn, [])
                       if b < tstart)
    n = 0
    for fn, ranges in spans.items():
        if fn in served or not any(b < tstart for _a, b in ranges):
            continue
        if re.search(r"\b" + re.escape(fn) + r"\s*\(", bodies):
            n += 1
    return n


def arg_text(text, open_paren):
    depth = 0
    for i in range(open_paren, min(len(text), open_paren + 4000)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return " ".join(text[open_paren + 1:i].split())
    return ""


def split_args(s):
    """Top-level comma split, respecting (), <> and []."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


# --- the derived wrapper set: C4's reach beyond a direct F1 call -------------
#
# C4 anchors on a call to an F1 name.  A function that takes a uid parameter and
# forwards it, unmodified, into an F1 sink defeats that anchor completely: the
# wrong uid is supplied at the WRAPPER's call site, and by the time control
# reaches the F1 call the argument is spelled with the wrapper's own parameter
# name, which matches nothing.  MEASURED: injecting a daemon uid at such a call
# site produced ZERO changed output lines across the whole report.
#
# WHY THIS IS DERIVED AND NOT A LIST OF NAMES.  The measured class was four
# members -- two wrappers and two functions wrapping those.  A list of four names
# would close those four and leave the shape open, which is worse than leaving it
# open honestly: a checker whose known gaps are patched reads as complete.  The
# second hop is what makes it a shape rather than a coincidence -- a wrapper that
# wraps a wrapper acquires new members without anyone deciding to add one.  So
# the set is recomputed from the tree on every run, seeded from F1_NAMES.
#
# WHAT COUNTS AS FORWARDING.  A `u32` parameter passed as a BARE top-level
# argument.  `sink(uid)` yes; `sink(uid + 1)`, `sink(other)` and `sink(f(uid))`
# no.  Argument lists come from `arg_text`/`split_args`, the same two helpers C4
# itself uses, so the wrapper scan and the clause cannot disagree about where an
# argument ends.
#
# WHAT THIS CANNOT SEE, all three measured rather than assumed:
#
#   * A uid stored on a struct and read back as `self.x` -- forwarding through a
#     FIELD rather than within one function body.  This is the real open hole and
#     it stays open deliberately; closing it is call-graph and data-flow work.
#     Measured mitigation, not a fix: the current class needs no such path -- all
#     four members forward a parameter directly, so nothing today hides there.
#   * A rebinding, `let x = uid;` then `sink(x)`.  Measured at raw 3, adjudicated
#     0: two were `let _ = operator_uid;` in a `cfg(not(macos))` arm, and the
#     third was `resolve_docker_route`'s Linux arm, where NOT collapsing is
#     correct because there is no gateway VM there.
#   * A parameter whose type is not the literal token `u32`.  MEASURED over the
#     daemon and sandbox-core: 233 parameters accepted; the excluded forms total
#     8 (`Option<u32>` x7, `Vec<u32>` x1) and NONE of them sits in a function
#     that calls a sink, so the fixpoint did not converge on a subset.  There are
#     zero `&u32` params, zero tuples carrying one, and zero `struct X(u32)`
#     newtypes, so there is no aliasing route in at present.
#
# The derivation runs over the scanned file only.  That is sufficient rather than
# lucky: workspace-wide, only two files contain a call to any F1 sink -- this one
# and gateway_lima.rs -- and every measured member is here.
WRAPPER_U32_PARAM = re.compile(r"\b([a-z_][a-z0-9_]*)\s*:\s*u32\b")

# A ceiling on the fixpoint, not an expectation.  The tree converges at hop 2;
# this exists so a pathological cycle cannot spin, and if it is ever REACHED the
# scope line will show a set far larger than four and that is the signal.
WRAPPER_MAX_HOPS = 6


def derive_wrappers(lines, spans, tstart):
    """{name: {hop, line, param, sink}} -- uid-forwarding wrappers, to fixpoint.

    Seeded from F1_NAMES and iterated: hop 1 forwards into an F1 sink, hop 2
    into a hop-1 member, and so on until a pass adds nothing.  Returning an
    EMPTY dict is the failure this set has to make visible, so `run` prints the
    size on every run and the self-test injects at a member's call site.
    """
    sinks = {n: 0 for n in F1_NAMES}
    members = {}
    for hop in range(1, WRAPPER_MAX_HOPS + 1):
        fresh = {}
        for fn, ranges in spans.items():
            if fn in sinks or fn in members:
                continue
            for a, b in ranges:
                if a >= tstart:
                    continue
                params = WRAPPER_U32_PARAM.findall(signature_of(lines, a, b))
                if not params:
                    continue
                body = []
                for l in lines[a - 1:min(b, len(lines))]:
                    if commentish(l):
                        continue
                    body.append(l.split("//")[0])
                body = "\n".join(body)
                for sink, shop in sinks.items():
                    if shop != hop - 1:
                        continue
                    for mo in re.finditer(
                            r"\b" + re.escape(sink) + r"\s*\(", body):
                        args = split_args(arg_text(body, mo.end() - 1))
                        hit = next((x for x in args if x in params), None)
                        if hit is not None:
                            fresh.setdefault(fn, dict(
                                name=fn, hop=hop, line=a, param=hit, sink=sink))
        if not fresh:
            break
        members.update(fresh)
        for n in fresh:
            sinks[n] = hop
    return members


def line_index(lines):
    starts, off = [], 0
    for l in lines:
        starts.append(off)
        off += len(l) + 1

    def lookup(idx):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            m = (lo + hi + 1) // 2
            if starts[m] <= idx:
                lo = m
            else:
                hi = m - 1
        return lo + 1
    return lookup


def host_scoped_only(raw, spans, fn, match_pos):
    """If the F1 result is bound and used ONLY for host-scoped reads, return the
    set of methods called on it; otherwise None (i.e. a real C4 violation).

    Conservative by construction: an unbound result, a binding whose uses cannot
    be resolved, or any single use outside HOST_SCOPED_QUERIES all return None.
    The carve-out has to be earned, not assumed.
    """
    stmt_start = max(raw.rfind(";", 0, match_pos), raw.rfind("{", 0, match_pos))
    mo = BINDING_RE.search(raw[stmt_start + 1:match_pos])
    if not mo:
        return None
    name = mo.group(1)
    a, b = min(spans.get(fn, [(0, 0)]), key=lambda r: r[1] - r[0])
    body = "\n".join(raw.split("\n")[a - 1:b])
    methods, bare = set(), 0
    for use in re.finditer(r"\b" + re.escape(name) + r"\b\s*(\.\s*([A-Za-z0-9_]+))?", body):
        if use.group(2):
            methods.add(use.group(2))
        else:
            bare += 1
    # `bare` counts the binding occurrence itself plus any use that is not a
    # method call (a move into a closure, a pass to a function).  One bare use
    # is the `let` itself; a move into `spawn_blocking(move || ...)` adds none,
    # because inside the closure the use IS a method call.  More than one bare
    # use means the handle escaped somewhere this cannot see -- refuse.
    if bare > 1 or not methods or not methods <= HOST_SCOPED_QUERIES:
        return None
    return name, methods


def collapsed_bindings(raw, spans, fn):
    """Names bound from a gateway_owner_uid(...) expression inside `fn`."""
    if fn not in spans:
        return set()
    a, b = min(spans[fn], key=lambda r: r[1] - r[0])
    body = "\n".join(raw.split("\n")[a - 1:b])
    return {m.group(1) for m in
            re.finditer(r"let\s+(?:mut\s+)?([A-Za-z0-9_]+)\s*(?::[^=]+)?=\s*[^;]*"
                        r"gateway_owner_uid\s*\(", body)}


def earned_owner_params(raw, spans):
    """Params named `owner_uid` whose EVERY call site passes a collapsed value.

    C5 accepts `owner_uid` at an F3 sink only for functions in this set.  The
    name alone would be an assertion by spelling -- exactly what this file
    exists to avoid -- so the acceptance is earned by checking the callers.
    Ported from the retired audit instrument described at F3_SINK_CALL.
    """
    lines = raw.split("\n")
    owner_fns = set()
    for name, ranges in spans.items():
        for a, b in ranges:
            if re.search(r"\bowner_uid\s*:\s*u32", signature_of(lines, a, b)):
                owner_fns.add(name)
    earned = set()
    for fname in owner_fns:
        sites, good = 0, 0
        for i, l in enumerate(lines, 1):
            if f"{fname}(" not in l or FN_RE.match(l):
                continue
            sites += 1
            caller = enclosing_fn(spans, i)
            last = re.search(rf"{re.escape(fname)}\s*\(([^;]*)\)", l)
            arg = split_args(last.group(1))[-1].strip() if last else ""
            if "gateway_owner_uid" in l or arg in collapsed_bindings(raw, spans, caller):
                good += 1
        if sites and sites == good:
            earned.add(fname)
    return earned


def test_region_start(lines):
    for i, l in enumerate(lines, 1):
        if l.strip().startswith("#[cfg(test)]"):
            return i
    return len(lines) + 2


# Everything at or after the first `#[cfg(test)]` is excluded from every clause.
# That cut is correct only while the test region is the LAST block in the file.
# A test module placed near the top -- beside a newly extracted function, say --
# silently hides most of the file behind a clean, green, exit-0 result.  That is
# the same silent-pass class as the two scope defects this file has already
# suffered, so it is asserted rather than left to whoever remembers to look.
MIN_SCANNED_FRACTION = 0.60

# --- the external landmark for the selector's denominator --------------------
#
# A denominator is only useful held against something derived independently of
# the thing it measures.  The landmark here is the ROUTER: every registered
# route names a handler, and a handler that cannot name whose request it is
# serving is the exception, not the rule.  The selector is derived from
# signatures; the route table is derived from registration.  Neither can drift
# into agreement with the other by accident.
#
# MEASURED at 7b3511d, and this is what makes the landmark worth printing:
#
#   corrected, type-anchored selector : 15/17 route handlers serving (88%)
#   the original defective selector   :  0/17 route handlers serving (0%)
#
# The collapsed selector covered NONE of them.  Nothing about "0 violations"
# would ever have shown that; the ratio shows it on the first line of output.
#
# It is a FLOOR, not an equality, and the two exceptions are why.  Re-measured
# against the committed revision rather than inherited from the line above, and
# the set difference is computed, not recalled: of 17 registered handlers, the
# two outside `served` are `health_check` and `version_handler`.  Both are
# legitimately out, for reasons that are properties of the endpoints:
#
#   version_handler  -- takes no parameters at all and returns
#                       env!("CARGO_PKG_VERSION").  There is no caller identity
#                       in scope to carry, in any spelling.
#   health_check     -- takes only `State`.  It is daemon-wide in *which
#                       sessions it lists* on purpose (it reads every row, not
#                       the caller's), so a caller identity in its signature
#                       would be the wrong shape.  Note this does NOT mean it
#                       probes a daemon-wide gateway: it derives a per-session
#                       operator from each row via
#                       `gateway_operator_for_session` and probes that one.  It
#                       is already converted; it is simply converted per row
#                       rather than per caller.
#
# So neither is a selector miss and neither is unconverted work.  A rule
# demanding 17/17 would be a false rule, and 15/17 is the correct ceiling until
# a route is added that takes a caller identity.
#
# What this ratio does NOT bound: it counts handlers the clauses APPLY to, not
# sinks the clauses COVER.  A handler inside `served` can still perform an
# owner-keyed call that no clause reads.  Being in the 15 is necessary for
# C1/C2/C4 to reach a site, never sufficient.
ROUTE_HANDLER = re.compile(
    r"\.route\s*\([^)]*?\b(?:get|post|delete|put|patch)\s*\(\s*([A-Za-z0-9_]+)")
MIN_HANDLER_COVERAGE = 0.50


def scope_report(raw, lines, tstart, served, spans):
    """(banner lines, hard_failure). Always reports denominators.

    Numerators are what checks print; denominators are what they hide. A clause
    reporting '0 violations' without 'over N sites of an expected ~M' is
    unfalsifiable, and this file has twice shipped a collapsed domain that
    reported zero. Both numbers go on every run, clean or not.
    """
    scanned = min(tstart - 1, len(lines))
    frac = scanned / max(1, len(lines))
    handlers = sorted(set(ROUTE_HANDLER.findall(raw)))
    covered = [h for h in handlers if h in served]
    ratio = len(covered) / max(1, len(handlers))
    out = [f"  scope: scanned {scanned}/{len(lines)} lines ({frac:.0%}); "
           f"test region starts at {tstart}",
           f"  scope: {len(served)} of {len(spans)} functions carry a caller "
           f"identity (C1/C2/C4 apply only to those)",
           f"  scope: landmark = the router; {len(covered)}/{len(handlers)} "
           f"registered route handlers are among them ({ratio:.0%})"]
    if handlers and ratio < MIN_HANDLER_COVERAGE:
        out += [
            "",
            "  *** SELECTOR COLLAPSE — REFUSING TO REPORT A VERDICT ***",
            f"  Only {len(covered)} of {len(handlers)} route handlers are "
            "classified as serving a caller.",
            "  Nearly every registered handler takes an operator identity, so a "
            "selector that",
            "  misses most of them is matching the wrong thing -- and every "
            "clean result below",
            "  would be clean because the clauses were applied to almost "
            "nothing.",
            f"  Handlers missed: "
            f"{', '.join(h for h in handlers if h not in covered)[:200]}",
        ]
    truncated = frac < MIN_SCANNED_FRACTION
    if truncated:
        out += [
            "",
            "  *** SCOPE FAILURE — REFUSING TO REPORT A VERDICT ***",
            f"  The first #[cfg(test)] sits at line {tstart}, leaving only "
            f"{frac:.0%} of the file scanned.",
            "  A clean result here would mean almost nothing: the clauses never "
            "saw most of the code.",
            "  Either the test region is no longer the last block in the file, "
            "or a test module",
            "  was inserted mid-file. Fix the cut before believing any verdict "
            "below.",
        ]
    return out, truncated, bool(handlers) and ratio < MIN_HANDLER_COVERAGE


# --- the carve-out's PREMISE, checked rather than attested -------------------
#
# The C4 host-scoped carve-out is sound exactly if every query in
# HOST_SCOPED_QUERIES is genuinely operator-invariant -- if its answer does not
# and cannot differ between two operators.  That is a property of the code, and
# a property of the code should be checked by code.
#
# This replaces an appeal to when the rule was written.  Provenance cannot
# settle it: the claim that the site was pre-registered is attested by the same
# author whose judgment is in question, so it cannot discharge the entrenchment
# concern however honestly it is offered.  The premise can settle it, and is
# checkable by someone who knows nothing about the rule's history.  If it holds
# the timing stops mattering; if it fails, no amount of pre-registration would
# have saved it.
#
# HOW: a `GatewayLimaManager` carries five pieces of per-operator state --
# `daemon_lima_home` (contains the owner uid), `instance_name`,
# `gateway_docker_socket`, `owner_uid`, and an `executor` through which every
# op goes via `owner_uid` (all 6 `self.executor.run(...)` sites in
# gateway_lima.rs pass `self.owner_uid` first -- 6 of 6, measured at 7b3511d).
# A method that never dereferences `self` cannot
# reach any of it, so its answer cannot vary by operator.  MEASURED at 7b3511d:
# 2 of the 27 `&self` methods in `impl GatewayLimaManager` dereference `self`
# zero times, and `lima_version` is one of them -- it shells out to
# `limactl --version` on the daemon's own PATH, with no LIMA_HOME, no instance
# name and no `sandbox-lima-helper` pivot.  25 of 27 do reach that state, so
# this is a real minority property rather than a triviality.
#
# Anything that fails this becomes a VIOLATION, not a carve-out.
HOST_SCOPED_IMPL = "GatewayLimaManager"
PER_OPERATOR_STATE = "self."


def impl_blocks(lines, type_name):
    """Line ranges of `impl <type_name>` blocks, by brace balance."""
    out = []
    for i, l in enumerate(lines, 1):
        if not re.match(r"^impl\s+" + re.escape(type_name) + r"\b", l):
            continue
        depth, j = 0, i
        while j <= len(lines):
            depth += lines[j - 1].count("{") - lines[j - 1].count("}")
            if depth == 0 and j > i:
                break
            j += 1
        out.append((i, j))
    return out


def host_scoped_premise(main_rs):
    """(violations, notes) -- re-derive the carve-out's premise every run."""
    gl = main_rs.parents[2] / "sandbox-core" / "src" / "gateway_lima.rs"
    if not gl.exists():
        return [("C4", 0, "<premise>",
                 f"carve-out premise UNCHECKABLE: {gl.name} absent")], []
    lines = gl.read_text().split("\n")
    spans = fn_spans(lines)
    blocks = impl_blocks(lines, HOST_SCOPED_IMPL)
    viol, notes = [], []
    for q in sorted(HOST_SCOPED_QUERIES):
        sites = [(a, b) for (a, b) in spans.get(q, [])
                 if any(s <= a <= e for s, e in blocks)]
        if not sites:
            viol.append(("C4", 0, q,
                         f"carve-out premise UNCHECKABLE: no `{q}` in "
                         f"impl {HOST_SCOPED_IMPL}"))
            continue
        for (a, b) in sites:
            body = "\n".join(lines[a - 1:min(b, len(lines))])
            derefs = sorted(set(re.findall(r"self\.([A-Za-z0-9_]+)", body)))
            if derefs:
                viol.append(("C4", a, q,
                             f"carve-out premise BROKEN: {q} reads "
                             f"self.{{{','.join(derefs)}}} -- its answer can "
                             "differ between operators, so it is NOT host-scoped"))
            else:
                notes.append(f"{q} (gateway_lima.rs:{a}) dereferences `self` "
                             f"0 times over {b - a + 1} lines")
    return viol, notes


# ===========================================================================
# C8 -- the broker's operation set stays CLOSED
# ===========================================================================
#
# This clause reads a different file from every other one -- the operator
# agent's protocol definition, not the daemon -- and it asks a different kind
# of question.  C0-C7 ask "what uid class does this site handle".  C8 asks
# whether the operation set on the wire is still closed: every op a typed
# variant with typed fields, and no field carrying a command, a path or a name
# that the agent would have to interpret and act on.  The constraint behind it
# is absolute and predates this file: NO FIX MAY ADD A NAME OR PATH FIELD TO AN
# OPERATION.  If a change appears to need one, that is a stop-and-ask.
#
# ---------------------------------------------------------------------------
# WHAT THIS CLAUSE ACTUALLY COVERS -- stated here so that a green cannot be
# read as the stronger claim.  It is a FIXED-NAME DENYLIST.  It watches five
# spellings that have carried pass-through before.  It CANNOT see a sixth
# free-form field under a name nobody has thought of yet: `cmd: String`,
# `target: String`, `path: PathBuf`, `extra: serde_json::Value` would every one
# of them pass silently.  So a green here means "no regression against a known
# shape".  It does NOT mean "the op set is closed".  The general property is
# not mechanically checkable from a denylist and is not claimed by this clause.
# Reviewing a new wire field is still a human act; this only catches the
# reappearance of a shape that has gone wrong before.
#
# ---------------------------------------------------------------------------
# WHY A COUNT AND NOT A ZERO.  Three of the five spellings are legitimately
# present today.  `vm: String` names a Lima instance the agent already owns and
# already addresses by name, so it carries no new authority.  `argv` appears
# twice inside the LOCAL RENDERING function that turns a typed op into an
# argument vector -- which is the correct direction of that dependency: typed
# in, argv out, never argv on the wire.  A clause that demanded zero would be
# permanently red and would be silenced within a week.  The signal is GROWTH
# against a recorded composition.
#
# ---------------------------------------------------------------------------
# WHY THE BASELINE IS DECLARED HERE, WHICH IS THE POINT OF THIS CLAUSE.  The
# ancestor of this check computed exactly these five counts and PRINTED them,
# as an observation that never gated, to be compared by a human against a
# number written down in a planning document.  That is not a check.  A
# comparison needs two operands, and one of the two was going to stop existing
# the moment the document was superseded.  Porting the counting without porting
# the baseline would have reproduced the same non-check with better formatting,
# so the constant lives here, beside the patterns, and gates the exit code.
#
# PROVENANCE OF THE NUMBERS.  Recorded composition, measured at 9b75a4a: 13
# hits total -- 11 `vm: String`, 2 `argv`, both `argv` inside the local
# rendering function.  Re-measured against the tree this clause was written
# for: identical in total AND in composition.  It is stated per spelling rather
# than as a single 13 because a per-spelling baseline catches a SWAP that a
# total cannot -- delete one `vm: String`, add one `socket: String`, and the
# total is still 13 while a path has appeared on the wire.
#
# IF YOU ARE HERE BECAUSE THIS WENT RED, changing a number below is not the
# repair.  The repair is to establish that the new field carries no name, path
# or command for the agent to interpret -- and if it does, the constraint above
# says stop and ask.  Raising a baseline is a DECISION to accept a wider wire.
# It should read like one in the diff, which is why these are five separate
# named numbers and not a sum.
WIRE_FILE = ("sandbox-agent", "src", "protocol.rs")
WIRE_RENDER_FN = "docker_argv"
WIRE_PASSTHRU = [
    (re.compile(r"\bargv\b"), "argv"),
    (re.compile(r"\bargs\s*:\s*Vec<String>"), "args: Vec<String>"),
    (re.compile(r"\bvm\s*:\s*String"), "vm: String"),
    (re.compile(r"socket\s*:\s*String"), "socket: String"),
    (re.compile(r"instance_name\s*:\s*String"), "instance_name: String"),
]
WIRE_BASELINE = {
    "argv": 2,                    # both inside WIRE_RENDER_FN; see above
    "args: Vec<String>": 0,
    "vm: String": 11,
    "socket: String": 0,
    "instance_name: String": 0,
}


def wire_op_set(main_rs, sites):
    """C8 -- the operation set on the broker wire must stay closed.

    Read the block above before changing anything here.  Two INDEPENDENT
    failures, which are deliberately not the same test:

    1. A spelling above its recorded baseline.  Growth, not presence.
    2. An `argv` hit OUTSIDE the local rendering function, at ANY count.  argv
       on the wire is a stop condition, not a budget, so this one has no
       baseline to grow against and cannot be satisfied by a smaller number.

    Returns (violations, notes).  Mutates `sites` with this clause's
    denominators, including one per spelling: a total alone cannot show that
    all five patterns are still live.
    """
    p = main_rs.parents[2].joinpath(*WIRE_FILE)
    if not p.exists():
        return [("C8", 0, "<wire>",
                 "op-set check UNCHECKABLE: " + "/".join(WIRE_FILE) +
                 " is absent -- this clause decided nothing")], []
    lines = p.read_text().split("\n")
    spans = fn_spans(lines)
    tstart = test_region_start(lines)
    if WIRE_RENDER_FN not in spans:
        # Fails CLOSED, and loudly.  If the rendering fn is renamed, every
        # legitimate `argv` would otherwise read as wire pass-through and the
        # clause would go red for the wrong reason -- so say WHY instead, and
        # make re-establishing the carve-out the obvious repair.  A rename
        # should force someone to restate the property, never inherit it.
        return [("C8", 0, "<wire>",
                 f"op-set check UNCHECKABLE: no fn `{WIRE_RENDER_FN}` in "
                 f"{p.name} -- the local-rendering carve-out cannot be "
                 "located, so no `argv` can be told from pass-through")], []
    found = collections.Counter({lbl: 0 for _, lbl in WIRE_PASSTHRU})
    first = {}
    viol = []
    scanned = 0
    for i, l in enumerate(lines, 1):
        if i >= tstart or commentish(l):
            continue
        scanned += 1
        for rx, lbl in WIRE_PASSTHRU:
            if not rx.search(l):
                continue
            found[lbl] += 1
            first.setdefault(lbl, i)
            sites["alt C8/" + lbl] += 1
            fn = enclosing_fn(spans, i)
            if lbl == "argv" and fn != WIRE_RENDER_FN:
                viol.append(("C8", i, fn,
                             f"argv OUTSIDE `{WIRE_RENDER_FN}` -- argv on the "
                             "wire is a stop condition at any count, not a "
                             "count to be baselined"))
    sites["C8"] = sum(found.values())
    sites["C8 wire lines scanned"] = scanned
    for lbl in sorted(found):
        n, base = found[lbl], WIRE_BASELINE[lbl]
        if n > base:
            viol.append(("C8", first.get(lbl, 0), enclosing_fn(
                spans, first.get(lbl, 0)) if lbl in first else "<wire>",
                f"`{lbl}` appears {n} times, above its recorded baseline of "
                f"{base} -- a wire field was added; raising the baseline is a "
                "decision to accept a wider wire, not a fix"))
    notes = [f"{lbl}={found[lbl]}/{WIRE_BASELINE[lbl]}" for lbl in sorted(found)]
    # BELOW baseline is not a violation -- a field being removed is the
    # direction this clause wants.  But it does make the constant stale, and a
    # stale constant is slack the next addition can hide inside, so say so.
    stale = [lbl for lbl in sorted(found) if found[lbl] < WIRE_BASELINE[lbl]]
    if stale:
        notes.append("BELOW baseline, so the constant now carries slack a "
                     "future addition could hide in -- lower it deliberately: "
                     + ", ".join(stale))
    return viol, notes


# Where each clause's violations live.  The report prints a file:line that a
# reader is meant to be able to open, and every clause but one reads the daemon
# entry point -- so a single hard-coded "main.rs" was right until C8 arrived
# and would now emit a real line number against the wrong file.
CLAUSE_FILE = {"C8": "protocol.rs"}


# Which counters must be non-zero for the run to mean anything, and what a
# zero would mean.  A clause that decided nothing is not a clean result; it is
# an absent result wearing one.  These are DECISION counts, not violation
# counts -- the whole point is that they stay non-zero on correct code.
DENOM_EXPECTED = {
    "C1": "no `state.container_runtime` / `state.runtimes` in the scanned "
          "region at all",
    "C2": "no `state.gateway_lima_manager` left in the scanned region at all",
    "C3": "the F2 sink spellings match nothing -- the C3 lesson repeating",
    "C4": "no F1 call inside any serving fn -- selector or F1 names have moved",
    "C5": "neither F3 sink is reached anywhere in the scanned region",
    "C6": "no F1 function has a body here to check",
    "C7": "the recovery latch is never touched in the scanned region",
    "C8": "not one of the five pass-through spellings matches anywhere in the "
          "wire file -- wrong file, or every spelling has moved",
    "C8 wire lines scanned": "the wire file read as empty, or the test-region "
                             "boundary swallowed the whole file",
    # A zero here would be GOOD NEWS if true -- C1/C2 would have no blind
    # region -- which is exactly why it is listed as unexplained rather than
    # exempted.  On a tree with 31 serving and 107 non-serving functions the
    # honest value is dozens; a zero means the name matching collapsed, and a
    # collapsed scope figure reads as reassurance.
    "blind region: non-serving fns called from a serving fn":
        "no non-serving function is called from a serving one -- implausible "
        "at this size; the name matching has collapsed",
    # The two counters that make the derived set falsifiable.  Both were
    # non-zero when the derivation was folded in (4 members, 15 call sites), so
    # a zero in either is a regression in the DERIVATION, not a clean tree --
    # and it is precisely the state in which the widening silently becomes a
    # no-op while every other number still looks healthy.
    "C4 derived wrappers":
        "the fixpoint returned no members -- seeded from F1_NAMES, so either "
        "those names have moved or the forwarding scan has collapsed",
    "C4 wrapper call sites":
        "the derived members exist but none is called anywhere -- the call "
        "scan collapsed, or the wrappers are now dead code",
}
# Counters that are legitimately zero today, each with the reason. Anything
# zero and NOT in this map is reported as a scope warning.
DENOM_ZERO_OK = {
    # These two are the ONLY zeros in this map that are also a success state,
    # so each names its own discriminator.  "the reads exist but none serve a
    # caller" (converted -- good) and "the field is gone and the clause is
    # vacuous" (rotted -- bad) print the identical zero here.  The parent
    # counter tells them apart, which is why C1/C2 are counted at two depths
    # rather than one: a vacuous clause takes the parent to zero too, and the
    # parent has no entry in this map, so it is reported.
    # These two said "converted, IF the parent is non-zero" until a constructed
    # tree showed the condition can be satisfied while an unconverted read sits
    # one hop below three serving handlers.  The clause was not merely blind to
    # it -- it printed an affirmative claim that the work was done.  They now
    # state only what was observed (nothing RAISED) and point at the scope
    # figure that sizes what was not looked at.  A zero here has never meant
    # "converted" and must never say so again.
    "C1 in a serving fn": "0 RAISED, which is not 0 present -- this clause "
                          "reaches only reads DIRECTLY inside a serving fn; "
                          "see `blind region` for what it cannot see",
    "C2 in a serving fn": "0 RAISED, which is not 0 present -- this clause "
                          "reaches only reads DIRECTLY inside a serving fn; "
                          "see `blind region` for what it cannot see",
    "C7 GatewayOwnership::PerOperator":
        "expected: PerOperator is the not-yet-built configuration",
    "alt NON_CALLER_UID/Uid::current()":
        "never fires on this tree; shown live by --self-test injection",
    "alt NON_CALLER_UID/bare literal":
        "never fires on this tree; shown live by --self-test injection",
    # Three of C8's five spellings have a baseline of zero, which is the whole
    # reason they are watched -- they are shapes that must never appear, not
    # shapes being budgeted.  A zero here is the success state, so it cannot
    # also be the alarm; what stands in for the alarm is the --self-test
    # injection, which shows each one firing on a planted field.  Without that
    # demonstration these three would be indistinguishable from dead patterns.
    "alt C8/args: Vec<String>":
        "baseline 0 -- must never appear; shown live by --self-test injection",
    "alt C8/socket: String":
        "baseline 0 -- must never appear; shown live by --self-test injection",
    "alt C8/instance_name: String":
        "baseline 0 -- must never appear; shown live by --self-test injection",
}


# EVERY counter is pre-seeded to zero.  A `collections.Counter` key that is
# never incremented does not appear in the report at all, so an absent clause
# reads as an omission rather than a zero -- the same silent-pass shape the rest
# of this file exists to close, reintroduced by the reporting itself.  Seeding
# forces every one of them to be printed and adjudicated.
DENOM_KEYS = (
    ["C1", "C2", "C1 in a serving fn", "C2 in a serving fn",
     "C3", "C4", "C4 F1 call sites", "C4 wrapper call sites",
     "C4 derived wrappers", "C5", "C6", "C7",
     "C7 GatewayOwnership::Shared", "C7 GatewayOwnership::PerOperator",
     "C8", "C8 wire lines scanned",
     "blind region: non-serving fns called from a serving fn"]
    + ["alt C8/" + lbl for _rx, lbl in WIRE_PASSTHRU]
    + ["alt " + cid + "/" + n
       for cid, _rx, _d, alts in FIELD_CLAUSES for n, _arx in alts]
    + ["alt C3/manager_for", "alt C3/registry().get_or_create"]
    + ["alt C4/" + n for n in F1_NAMES]
    + ["alt C5/gateway_lima_managers.get_or_create",
       "alt C5/gateway_docker_route"]
    + ["alt C7/for_owner", "alt C7/is_recovering"]
    + ["alt NON_CALLER_UID/" + n for n, _ in NON_CALLER_UID_ALTS]
)


def denominator_report(sites):
    """Per-clause decision counts, with every `|` alternative broken out."""
    out = ["  denominators (sites each clause DECIDED on, not violations):"]
    keys = sorted(sites, key=lambda k: (k.startswith("alt "), k))
    for k in keys:
        n = sites[k]
        note = ""
        if n == 0:
            # A zero is a QUESTION, not a verdict.  For an alternative it means
            # one of: the spelling is wrong (the C3 lesson), the construct does
            # not exist at this revision (running `--rev 70a55f6` puts
            # `resolve_docker_route` at zero, correctly -- it had not been
            # extracted yet), or the case simply does not occur here.  The
            # report cannot tell them apart; it can refuse to hide the zero.
            default = ("no site of this spelling in the scanned region -- "
                       "wrong spelling, or absent at this revision?"
                       if k.startswith("alt ") else "this clause decided nothing")
            note = ("  <-- " + DENOM_ZERO_OK[k] if k in DENOM_ZERO_OK
                    else "  <-- ZERO, UNEXPLAINED: " +
                    DENOM_EXPECTED.get(k, default))
        out.append(f"    {k:<44} {n:>3}{note}")
    for k, why in DENOM_EXPECTED.items():
        if sites.get(k, 0) == 0:
            out.append(f"    *** {k} DECIDED NOTHING -- {why}")
    return out


def run(path, quiet=False):
    """Returns (violations, accepted).

    Each is a list of (clause, lineno, fn, text[, why]).  An empty `violations`
    is clean; `accepted` holds sites that meet a stated contract carve-out and
    is printed rather than hidden -- a carve-out nobody sees is an allowlist.
    """
    raw = path.read_text()
    lines = raw.split("\n")
    spans = fn_spans(lines)
    served = serving_fns(lines, spans)
    tstart = test_region_start(lines)
    lno_of = line_index(lines)
    viol, accepted = [], []

    # Per-clause DENOMINATORS.  A violation count is a numerator; on its own it
    # cannot distinguish correct code from a clause that decided nothing.  Each
    # counter below is incremented at the point the clause actually reaches a
    # decision, so it measures the check rather than a model of it, and every
    # `|` alternative is counted separately for the reason NON_CALLER_UID_ALTS
    # gives.
    sites = collections.Counter({k: 0 for k in DENOM_KEYS})

    # The derived wrapper set. Recomputed from the tree, never listed -- see the
    # section comment on `derive_wrappers`. Its per-member counters are seeded
    # here for the same reason every other counter is: a member whose call sites
    # all vanished must print a zero rather than disappear from the report.
    wrappers = derive_wrappers(lines, spans, tstart)
    for _n in wrappers:
        sites["alt C4/" + _n] = 0
    sites["C4 derived wrappers"] = len(wrappers)
    c4_call = re.compile(
        r"\b(" + "|".join(list(F1_NAMES) + sorted(wrappers)) + r")\s*\(")

    def count_non_caller(arg):
        for name, rx in NON_CALLER_UID_ALTS:
            if rx.search(arg):
                sites["alt NON_CALLER_UID/" + name] += 1

    # C1/C2 -- an F3 output read inside a function that is serving a caller.
    # Scanned over the whole file text, not line by line: rustfmt splits these
    # field accesses across lines and a line-anchored scan matches neither of
    # C1's two real sites.  See the note under FIELD_CLAUSES for the measurement.
    for cid, rx, _desc, alts in FIELD_CLAUSES:
        for mo in rx.finditer(raw):
            lno = lno_of(mo.start())
            if lno >= tstart or commentish(lines[lno - 1]):
                continue
            sites[cid] += 1
            for name, arx in alts:
                if arx.match(mo.group(0)):
                    sites["alt " + cid + "/" + name] += 1
            fn = enclosing_fn(spans, lno)
            if fn in served:
                sites[cid + " in a serving fn"] += 1
                viol.append((cid, lno, fn, " ".join(
                    raw[mo.start():mo.start() + 110].split())[:70]))

    # C3 -- an F2 sink receiving a collapsed uid.  Mirror image of C1/C2, and
    # the more dangerous direction: while the switch is OFF the collapse is the
    # identity on the daemon's own uid, so the bug is invisible in the tested
    # configuration and fires only once the switch is ON -- the configuration
    # this work exists to enable.
    for mo in F2_SINK.finditer(raw):
        lno = lno_of(mo.start())
        if lno >= tstart or commentish(lines[lno - 1]):
            continue
        sites["C3"] += 1
        sites["alt C3/" + ("manager_for" if ".manager_for" in mo.group(0)
                           else "registry().get_or_create")] += 1
        if COLLAPSE_CALL.match(arg_text(raw, raw.index("(", mo.end() - 1))):
            viol.append(("C3", lno, enclosing_fn(spans, lno),
                         lines[lno - 1].strip()[:70]))

    # C4 -- an F1 entry point receiving a uid that is not the caller's, inside a
    # function that has a caller.  This is the clause that measures the contract
    # rather than the spelling: it fires on correctly-named, currently-spelled
    # code whose only fault is the uid CLASS being passed.
    # `c4_call` is F1_NAMES PLUS the derived wrapper set, so a wrong uid handed
    # to a wrapper is the same violation as one handed to the sink it forwards
    # to. The two populations are counted apart: folding wrappers into the
    # existing `C4 F1 call sites` figure would move a number for an instrument
    # reason and make it unreadable as a measurement of anything.
    for mo in c4_call.finditer(raw):
        lno = lno_of(mo.start())
        if lno >= tstart or commentish(lines[lno - 1]):
            continue
        if re.match(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s", lines[lno - 1]):
            continue  # the definition, not a call
        if mo.group(1) in F1_NAMES:
            sites["C4 F1 call sites"] += 1
        else:
            sites["C4 wrapper call sites"] += 1
        sites["alt C4/" + mo.group(1)] += 1
        fn = enclosing_fn(spans, lno)
        if fn not in served:
            continue
        sites["C4"] += 1
        for arg in split_args(arg_text(raw, raw.index("(", mo.end() - 1))):
            if not NON_CALLER_UID.search(arg):
                continue
            count_non_caller(arg)
            carve = host_scoped_only(raw, spans, fn, mo.start())
            if carve is not None:
                bind, uses = carve
                accepted.append(("C4", lno, fn, f"{mo.group(1)}(.. {arg} ..)",
                                 f"`{bind}` used only for {sorted(uses)}"))
            else:
                viol.append(("C4", lno, fn,
                             f"{mo.group(1)}(.. {arg} ..)"[:70]))
            break

    # C5 -- an F3 sink must receive an ALREADY-COLLAPSED owner uid.  See
    # F3_SINK_CALL for where this came from, and for why it asks the contract
    # question rather than keeping an approved-function list.
    earned = earned_owner_params(raw, spans)
    for mo in F3_SINK_CALL.finditer(raw):
        lno = lno_of(mo.start())
        if lno >= tstart or commentish(lines[lno - 1]):
            continue
        sites["C5"] += 1
        sites["alt C5/" + ("gateway_lima_managers.get_or_create"
                           if "gateway_lima_managers" in mo.group(0)
                           else "gateway_docker_route")] += 1
        fn = enclosing_fn(spans, lno)
        arg = split_args(arg_text(raw, raw.index("(", mo.end() - 1)))
        arg = arg[-1] if arg else ""
        # The daemon's own uid IS an owner uid and needs no collapse: with the
        # switch off `gateway_owner_uid` answers `getuid()` for everyone, and
        # with it on it answers the daemon for the daemon.  Startup relies on
        # this -- `state.docker` is the factory evaluated at `daemon_uid`.
        # BUT only outside a request-serving function: answering a caller's
        # request from the daemon's own gateway is the defect C1/C2 exist for,
        # and it must not be let in through this door.
        daemon_own = NON_CALLER_UID.search(arg) and fn not in served
        ok = ("gateway_owner_uid" in arg
              or arg in collapsed_bindings(raw, spans, fn)
              or daemon_own
              or (arg == "owner_uid" and fn in earned))
        if not ok:
            viol.append(("C5", lno, fn,
                         f"F3 sink <- uncollapsed {arg!r}"[:70]))

    # C6 -- every F1 function must actually perform the collapse, or delegate
    # to another F1 function that does.  Without this the whole contract can be
    # emptied out in one line while every call site still reads correctly.
    # No cfg/Linux-arm excuse: the retired instrument allowed a body to pass if
    # the collapse appeared in *any* cfg arm, and that excuse is what let a
    # gutted body through.
    for name in F1_NAMES:
        if name == "gateway_owner_uid" or name not in spans:
            continue
        sites["C6"] += 1
        a, b = min(spans[name], key=lambda r: r[1] - r[0])
        body = "\n".join(lines[a - 1:b])
        others = [o for o in F1_NAMES if o != name]
        if "gateway_owner_uid" in body:
            continue
        if any(re.search(r"\b" + re.escape(o) + r"\s*\(", body) for o in others):
            continue
        viol.append(("C6", a, name,
                     "F1 fn neither collapses nor delegates to an F1 fn"))

    # C7 -- the gateway-recovery latch, the third F3 owner-keyed sink.
    #
    # Order matters: the earning is established first, because whether a
    # `shard.owner_uid` key is acceptable depends on how the shard was built.
    shared_collapsed, perop_sites = True, []
    for mo in OWNERSHIP_SHARED.finditer(raw):
        lno = lno_of(mo.start())
        if lno >= tstart or commentish(lines[lno - 1]):
            continue
        sites["C7 GatewayOwnership::Shared"] += 1
        if "gateway_owner_uid" not in arg_text(raw, raw.index("(", mo.end() - 1)):
            shared_collapsed = False
            viol.append(("C7", lno, enclosing_fn(spans, lno),
                         "GatewayOwnership::Shared <- uncollapsed uid; every "
                         "shard key downstream is now raw"))
    for mo in OWNERSHIP_PEROP.finditer(raw):
        lno = lno_of(mo.start())
        if lno < tstart and not commentish(lines[lno - 1]):
            perop_sites.append(lno)
    sites["C7 GatewayOwnership::PerOperator"] = len(perop_sites)
    if perop_sites:
        # PerOperator is not a defect -- it is where this work is going, and
        # under it a shard key IS an owner uid. What it changes is everything
        # keyed to the OTHER side of the latch, plus the driver.
        for (a, b) in spans.get(RECOVERY_DRIVER, []):
            for i in range(a, min(b, len(lines)) + 1):
                if SINGLETON_DRIVE.search(lines[i - 1]) and not commentish(lines[i - 1]):
                    viol.append(("C7", i, RECOVERY_DRIVER,
                                 f"GatewayOwnership::PerOperator at {perop_sites[0]} "
                                 "shards per owner while this still drives the "
                                 "singleton -- one VM restarted once per shard"))

    for mo in LATCH_SINK.finditer(raw):
        lno = lno_of(mo.start())
        if lno >= tstart or commentish(lines[lno - 1]):
            continue
        sites["C7"] += 1
        sites["alt C7/" + ("for_owner" if "for_owner" in mo.group(0)
                           else "is_recovering")] += 1
        fn = enclosing_fn(spans, lno)
        arg = arg_text(raw, raw.index("(", mo.end() - 1)).strip()
        # Under PerOperator the writer keys per operator, so a reader still
        # keyed off the daemon's uid polls an entry nobody writes. Checked
        # before the acceptances below because the argument here is a
        # *correctly collapsed* daemon uid -- right expression, wrong side.
        if perop_sites and NON_CALLER_UID.search(arg):
            viol.append(("C7", lno, fn,
                         f"shards keyed per operator at {perop_sites[0]}, but "
                         "this keys the latch off the daemon's uid -- nobody "
                         "writes the entry it polls"))
            continue
        ok = ("gateway_owner_uid" in arg
              or arg in collapsed_bindings(raw, spans, fn)
              or (NON_CALLER_UID.search(arg) and fn not in served)
              or (OWNER_FIELD.match(arg) and (shared_collapsed or perop_sites))
              or (arg == "owner_uid" and fn in earned))
        if not ok:
            viol.append(("C7", lno, fn,
                         f"recovery latch keyed on uncollapsed {arg!r} -- "
                         "writer and reader will key different entries"))

    # C0 -- the scope guard, evaluated LAST so it is reported alongside the
    # clause results, but carried as a violation so a truncated run cannot exit
    # 0.  A scope failure is not an aside to a green verdict; it means there was
    # no verdict.
    banner, truncated, collapsed = scope_report(raw, lines, tstart, served, spans)
    if truncated:
        viol.append(("C0", tstart, "<file>",
                     f"only {tstart - 1}/{len(lines)} lines scanned -- "
                     "test region is not the last block"))
    if collapsed:
        viol.append(("C0", 0, "<selector>",
                     "selector matches under half the registered route "
                     "handlers -- the clauses were applied to almost nothing"))

    # The carve-out's premise, re-derived per run. Checked only when the
    # carve-out was actually exercised: a run that accepted nothing is not
    # relying on it, and reporting on an unused rule is noise.
    if accepted:
        pviol, pnotes = host_scoped_premise(path)
        viol.extend(pviol)
        banner.append(
            "  premise: host-scoped set = "
            + ", ".join(sorted(HOST_SCOPED_QUERIES))
            + (f"; {'; '.join(pnotes)}" if pnotes else "")
            + (" -- BROKEN, see violations below" if pviol else
               " -- operator-invariant, so the carve-out holds"))

    # C8 reads the wire file, not the daemon, and is unconditional: unlike the
    # premise above it is not contingent on anything this run happened to find.
    # Sizes what C1/C2 cannot reach. Computed, never compared -- see the
    # docstring for why this is a scope figure and not a baseline.
    sites["blind region: non-serving fns called from a serving fn"] = \
        blind_region(lines, spans, served, tstart)

    # The derived wrapper set, printed as a SCOPE FIGURE: computed every run,
    # compared to nothing, gating nothing. A derived set that silently collapses
    # to empty is how a widened check becomes a no-op that reports success, and
    # the only defence is that its size is visible in ordinary output. There is
    # deliberately no baseline to edit -- if these names or counts move, that is
    # the tree changing, not a check to repair.
    if wrappers:
        banner.append(
            "  scope: derived wrapper set (seeded from F1_NAMES, to fixpoint): "
            + "; ".join(
                "%s hop%d/%d sites" % (m["name"], m["hop"],
                                       sites["alt C4/" + m["name"]])
                for m in sorted(wrappers.values(),
                                key=lambda d: (d["hop"], d["name"])))
            + " -- %d member(s), %d call site(s)"
            % (len(wrappers),
               sum(sites["alt C4/" + n] for n in wrappers)))
    else:
        banner.append(
            "  scope: derived wrapper set is EMPTY -- C4 covers direct F1 calls "
            "only; the derivation found nothing and may have collapsed")

    wviol, wnotes = wire_op_set(path, sites)
    viol.extend(wviol)
    banner.append("  wire op set (found/baseline): " + "; ".join(wnotes)
                  if wnotes else "  wire op set: NOT CHECKED, see violations")

    banner.extend(denominator_report(sites))

    if not quiet:
        for b in banner:
            print(b)
        for cid, i, fn, s in sorted(viol, key=lambda v: (v[1], v[0])):
            f = CLAUSE_FILE.get(cid, "main.rs")
            print(f"  {cid} VIOLATION {f}:{i} fn {fn}: {s}")
        for cid, i, fn, s, why in sorted(accepted, key=lambda v: (v[1], v[0])):
            f = CLAUSE_FILE.get(cid, "main.rs")
            print(f"  {cid} accepted  {f}:{i} fn {fn}: {s}  [{why}]")
    return viol, accepted


# ---------------------------------------------------------------------------
# RED demonstration.
#
# Each injection is a CONTRACT violation -- a call passing the wrong uid class
# -- not a string chosen to match a pattern.  C3 and C4 spell every identifier
# correctly and currently; only the uid class is wrong.  C1 and C2 cannot be
# built that way, which is the finding rather than an oversight: see the header.
#
# Injection anchors are located structurally (the opening brace of a named
# serving function), not by matching a source line, so a rename of the code
# inside the handler does not silently disarm the demonstration.  If the anchor
# function is gone the self-test says so loudly instead of passing vacuously.
# ---------------------------------------------------------------------------
INJECT_FN = "stop_session"
INJECTIONS = [
    ("C1", "    let bad_rt = state.container_runtime.clone();",
     "F3 output (the daemon-built container runtime, which carries the daemon's "
     "own Docker route inside it) reached while serving a caller"),
    ("C2", "    let bad_mgr = state.gateway_lima_manager.clone();",
     "F3 output (daemon-built gateway manager) used while serving a caller"),
    ("C3", "    let bad = state.lima_runtime.manager_for("
            "sandbox_core::gateway_owner_uid(operator.uid));",
     "F2 session registry handed a COLLAPSED uid"),
    ("C3b", "    let bad = state.lima_runtime.registry().get_or_create("
             "sandbox_core::gateway_owner_uid(operator.uid));",
     "F2, second spelling -- the one the previous clause silently missed"),
    ("C4", "    let bad = state.docker_route_for_operator(state.daemon_uid);",
     "F1 handed the DAEMON's uid while serving a caller -- every name correct"),
    # The two injections below exist because the per-clause census found their
    # NON_CALLER_UID alternatives at ZERO on this tree.  A zero there is
    # ambiguous -- dead spelling, or a case the code does not contain -- and the
    # C3 lesson is what the first reading costs.  These resolve it: the
    # alternatives are demonstrably live, so the zeros are absence of the
    # defect, not absence of a check.
    ("C4", "    let bad = state.docker_route_for_operator("
            "nix::unistd::Uid::current().as_raw());",
     "F1 handed the daemon's uid by its OTHER spelling -- exercises the "
     "`Uid::current()` alternative of NON_CALLER_UID, which matches nothing "
     "on the clean tree"),
    ("C4", "    let bad = state.docker_route_for_operator(0);",
     "F1 handed a LITERAL uid -- exercises the bare-literal alternative of "
     "NON_CALLER_UID, also at zero on the clean tree"),
    # The aliveness buy-back for the DERIVED wrapper set.  Every other injection
    # here targets a name the file holds as a constant; this one targets a name
    # the file computes.  `gateway_for_probes` is never listed -- it has to be
    # rediscovered from the tree on every run -- so if the derivation collapses
    # to empty, C4 stops covering it and this goes GREEN where it must be RED.
    # A silent no-op is precisely what a widened check degrades into, and this
    # is the only thing standing between that and a clean-looking report.
    # MEASURED: injecting exactly this produced ZERO changed output lines before
    # the derivation existed.
    ("C4", "    let bad = gateway_for_probes(&state, state.daemon_uid);",
     "a DERIVED wrapper handed the daemon's uid while serving a caller -- the "
     "wrapper forwards it into F1 under its own parameter name, so the direct "
     "F1 anchor never sees it; RED here proves the derived set is live"),
    ("C4", "    let bad = probe_gateway_status(&state, &session, "
           "state.daemon_uid).await;",
     "the same defect at HOP 2 -- probe_gateway_status forwards into "
     "gateway_for_probes, which forwards into F1.  The case above proves only "
     "that the derived set is NON-EMPTY and contains a hop-1 member: a "
     "derivation that computed gateway_for_probes and stopped would pass it "
     "identically while silently dropping 5 of 15 call sites.  This case is "
     "what makes the difference between a one-hop scan and a fixpoint a "
     "RED/GREEN rather than an asserted 'hops 3-5 added zero' in a log line"),
    ("C5", "    let bad = (state.gateway_docker_route)(operator.uid);",
     "F3 route factory reached directly with a RAW operator uid "
     "(measured GREEN under C1-C4 before this clause existed)"),
    ("C5", "    let bad = state.gateway_lima_managers.get_or_create(operator.uid);",
     "F3 gateway registry reached directly with a RAW operator uid "
     "(measured GREEN under C1-C4 before this clause existed)"),
    ("C7", "    let bad = state.gateway_recovering.for_owner(operator.uid);",
     "recovery latch WRITTEN under a raw operator uid while the monitor polls "
     "the collapsed one (measured GREEN under C1-C6 before this clause existed)"),
    ("C7", "    let bad = state.gateway_recovering.is_recovering(operator.uid);",
     "recovery latch READ under a raw operator uid -- the mirror direction, "
     "also GREEN under C1-C6"),
]

# C8's demonstrations mutate the WIRE file, not main.rs, so they get their own
# table.  The anchor is an op enum's opening line -- structural, like INJECT_FN
# -- and each injection lights exactly ONE spelling, because a demonstration
# that only moved the total would pass equally on a clause that had collapsed
# to counting and no longer knew which pattern matched.  The assertion below is
# on the label appearing in the violation text, not on the count changing.
#
# FIVE, NOT TWO.  Three of the five spellings sit at a baseline of zero, and
# this file's existing rule -- the reason two extra acceptance controls exist
# for the carve-out -- is that a term which never fires on the tree is
# indistinguishable from a dead one until something makes it fire.  A zero
# baseline makes that worse, not better: it is the state the clause is *for*,
# so the ordinary denominator alarm is switched off for it by design (see
# DENOM_ZERO_OK).  With the alarm off, the injection is the only thing standing
# between "this spelling has never appeared" and "this pattern has not compiled
# since someone edited it".  So every spelling with a zero baseline gets one.
WIRE_ENUM_ANCHOR = "pub enum InVmOp {"
WIRE_INJECTIONS = [
    ("vm: String", "    InjectedProbe { vm: String },",
     "a TWELFTH `vm: String` -- one above the recorded 11, the growth case on "
     "a spelling that is legitimately present"),
    ("args: Vec<String>", "    InjectedArgs { args: Vec<String> },",
     "an argument vector as a wire field -- baseline zero, so this is the only "
     "thing that ever shows the pattern alive"),
    ("socket: String", "    InjectedSocket { socket: String },",
     "a socket PATH as a wire field -- also baseline zero"),
    ("instance_name: String", "    InjectedInstance { instance_name: String },",
     "an instance NAME as a wire field -- also baseline zero, and the exact "
     "shape the no-name-field constraint forbids"),
]
# argv gets a different shape because it is a different test.  The other four
# are count-vs-baseline; this one must fire from OUTSIDE the local rendering
# function at ANY count, so it is demonstrated by a free function that takes an
# argv rather than by a field added to an enum.  Injecting it as a fifth
# variant would have tested the count path again and left the stop condition
# undemonstrated while looking like coverage.
WIRE_ARGV_INJECTION = (
    WIRE_ENUM_ANCHOR,
    "pub fn _injected_passthru(argv: Vec<String>) -> usize {\n"
    "    argv.len()\n"
    "}\n" + WIRE_ENUM_ANCHOR)

# C6 cannot be demonstrated by inserting a line -- its defect is a DELETION.
# Removing the collapse from an F1 body leaves every call site reading
# correctly and every other clause green, which is why it needs its own shape.
DELETIONS = [
    ("C6", "    let owner_uid = sandbox_core::gateway_owner_uid(operator_uid);",
     "    let owner_uid = operator_uid;",
     "the collapse deleted from an F1 body -- every operator silently gets the "
     "daemon's gateway, and nothing at any call site changes"),
    ("C7",
     "sandbox_core::GatewayOwnership::Shared(sandbox_core::gateway_owner_uid("
     "state.daemon_uid)),",
     "sandbox_core::GatewayOwnership::Shared(state.daemon_uid),",
     "the collapse deleted where the shard key is BUILT. This is the control "
     "for C7's earned acceptance: `shard.owner_uid` is only trustworthy "
     "because of this one expression, so removing it must both flag the "
     "construction and withdraw the acceptance downstream"),
]


# ---------------------------------------------------------------------------
# NON_CALLER_UID controls for C5 and C7.
#
# C4 consults NON_CALLER_UID as a VIOLATION TRIGGER and the two injections above
# exercise it.  C5 and C7 consult the same regex in two shapes a red injection
# cannot reach:
#
#   C5's `daemon_own` and C7's third `ok` term are ACCEPTANCES -- their job is
#   to keep a site GREEN.  An injection that turns a clause red never evaluates
#   them.  And an acceptance that has silently stopped matching does not
#   announce itself by failing: it announces itself by swallowing a real
#   violation somewhere else, which is the direction nothing detects.  So each
#   gets a PAIR -- the site minus the stronger term, which must stay GREEN and
#   so proves this term is what holds it up; and the same site with an argument
#   matching neither term, which must go RED and so proves the term is not
#   simply inert.  One half alone proves nothing: a dead clause is green too.
#
#   C7's `perop_sites and NON_CALLER_UID` IS a trigger, but it is gated on a
#   `GatewayOwnership::PerOperator` site and the tree has none.  Unreachable
#   rather than untested, so the control supplies the gate.
#
# The two acceptances are NOT equally alive, which is the finding rather than a
# detail.  Deliberately no line numbers here: line numbers in a comment rot
# silently, and the function names are what a reader can actually find.
#   - C5's is SOLE at the startup site that builds the daemon's own route
#     (`gateway_docker_route(daemon_uid)` in `fn main`).  Nothing else accepts
#     that site; if this term stops matching, the checker goes red on correct
#     code, which is loud.
#   - C7's third `ok` term holds NO site on the current tree.  It is a SPELLING
#     regex -- `daemon_uid`, `Uid::current()`, or a bare integer -- and the two
#     live latch sites are held by the other terms: the read in
#     `fn gateway_monitor` by `gateway_owner_uid`-in-argument, and the write by
#     the `shard.owner_uid` term.  Note that the term remains semantically RIGHT
#     for its site: it accepts a uid that did not come from a caller, and a
#     background monitor has no caller.  What changed is that the monitor now
#     spells its argument through the collapse, which the earlier term never
#     needed to match.  So it is currently redundant where it used to be
#     load-bearing -- and a redundant acceptance is INDISTINGUISHABLE from a dead
#     one by any observation of a green tree, which is exactly why it gets a
#     control instead of an argument.  The pair below mutates the site INTO the
#     shape only this term can carry, and then out of reach of every term.
#
# Each mutation asserts its anchor is UNIQUE before applying.  A `str.replace`
# that silently hits three sites is not a control -- it perturbs the tree in
# ways the assertion does not name, and the first draft of these did exactly
# that, going red for reasons that had nothing to do with the term under test.
#
# THESE ANCHORS ARE COUPLED TO THE TREE, and that is the one part of this file
# that can be invalidated by an ordinary refactor.  The coupling is deliberate:
# a control that mutates a site has to name the site.  It is safe because the
# breakage is LOUD -- a renamed or rekeyed site makes the anchor match zero
# times, and `--self-test` prints ANCHOR NOT UNIQUE and exits 1 rather than
# quietly demonstrating nothing.  When that happens the repair is to re-anchor
# the control at the site's new spelling, after first establishing that the
# property the control was defending still holds there.  Do NOT delete the
# control to make the self-test green: that trades a loud failure for a silent
# one, which is the inversion this whole file exists to prevent.
# ---------------------------------------------------------------------------
ACCEPTANCE_CONTROLS = [
    ("C5", "let docker_route = gateway_docker_route(daemon_uid);",
           "let docker_route = gateway_docker_route(startup_uid);", False,
     "C5's `daemon_own` is the ONLY term accepting the daemon's own route at "
     "startup -- rename the argument and correct code goes red"),
    ("C7", "is_recovering(sandbox_core::gateway_owner_uid(operator_uid))",
           "is_recovering(state.daemon_uid)", True,
     "C7's third term carrying a site ALONE -- collapse removed, argument still "
     "a uid no caller supplied, outside a serving fn"),
    ("C7", "is_recovering(sandbox_core::gateway_owner_uid(operator_uid))",
           "is_recovering(state.some_uid)", False,
     "the same site with an argument matching NEITHER term -- proves the green "
     "above is this acceptance and not a clause that cannot fire"),
]

# C7's NON_CALLER_UID TRIGGER needs TWO mutations, not one, and the second is
# the whole reason this control still exists.
#
# Mutation 1 supplies the gate: the trigger only fires where the tree has a
# `GatewayOwnership::PerOperator` site, and it has none.
#
# Mutation 2 supplies the DEFECT.  The gate alone used to be enough, back when
# the monitor read the latch under the daemon's own uid: turn the switch on and
# that reader is instantly wrong.  The monitor now resolves the session's
# operator and reads under `gateway_owner_uid(operator_uid)`, which is correct
# under PerOperator, so the gate alone leaves the tree legitimately green -- and
# a control whose mutation no longer produces a defect reports STILL GREEN,
# which is indistinguishable from the trigger being dead.
#
# Restoring the daemon-keyed spelling is therefore not a trick to get the
# control red again; it reconstructs the exact defect the reader was changed to
# fix, which makes this pair a regression test for it.
PEROP_GATE = (
    ("\nasync fn gateway_monitor",
     "\nfn _mode() -> sandbox_core::GatewayOwnership {\n"
     "    sandbox_core::GatewayOwnership::PerOperator(0)\n}\n"
     "async fn gateway_monitor"),
    ("is_recovering(sandbox_core::gateway_owner_uid(operator_uid))",
     "is_recovering(sandbox_core::gateway_owner_uid(state.daemon_uid))"),
)


def non_caller_controls(main_rs, ok, base):
    original = main_rs.read_text()
    print("NON_CALLER_UID beyond C4: the C5 and C7 consultations, which are "
          "acceptances a red injection cannot reach")
    for cid, find, repl, want_green, why in ACCEPTANCE_CONTROLS:
        n = original.count(find)
        print(f"  {cid}: {why}")
        if n != 1:
            print(f"    -> ANCHOR NOT UNIQUE ({n} occurrences) -- an unscoped "
                  "mutation proves nothing; control did not run")
            ok = False
            continue
        main_rs.write_text(original.replace(find, repl))
        v = new_since(base, run(main_rs, quiet=True)[0])
        main_rs.write_text(original)
        print(f"      {repl.strip()[:88]}")
        if want_green:
            if not v:
                print("    -> GREEN, and with the stronger term gone this "
                      "acceptance is the only thing holding the site")
            else:
                print(f"    -> {len(v)} NEW violation(s) -- the acceptance did "
                      "not carry the site, so the pair establishes nothing")
                ok = False
        else:
            hit = [x for x in v if x[0] == cid]
            if hit:
                print(f"    -> RED, {cid} flagged at main.rs:{hit[0][1]} in fn "
                      f"{hit[0][2]}")
            else:
                print(f"    -> STILL GREEN -- {cid} accepts an argument no term "
                      "matches; the acceptance is unfalsifiable")
                ok = False

    print("  C7: NON_CALLER_UID as a VIOLATION trigger -- needs both a "
          "`GatewayOwnership::PerOperator` site, which the tree has none of, "
          "and a\n      daemon-keyed latch read, which the tree no longer has "
          "either. The control supplies each in turn.")
    mutated = original
    for find, repl in PEROP_GATE:
        if mutated.count(find) != 1:
            print(f"    -> ANCHOR NOT UNIQUE ({mutated.count(find)}) for "
                  f"{find.strip()[:60]!r} -- control did not run")
            return False
        mutated = mutated.replace(find, repl)
    main_rs.write_text(mutated)
    v = new_since(base, run(main_rs, quiet=True)[0])
    main_rs.write_text(original)
    hit = [x for x in v if "nobody writes the entry it polls" in x[3]]
    if hit:
        print(f"    -> RED at main.rs:{hit[0][1]} in fn {hit[0][2]} -- writer "
              "shards per operator while this reader stays keyed on the daemon")
    else:
        print("    -> STILL GREEN -- the trigger cannot fire even with its "
              "gate satisfied and the defect restored")
        ok = False
    return ok


def violation_key(v):
    """A violation's identity ACROSS an edit that moves lines.

    Deliberately excludes the line number.  Every demonstration below inserts or
    replaces text, which shifts every line beneath it, so a line-keyed identity
    would report the entire tail of the file as newly broken and each
    demonstration would "pass" on violations it did not cause.
    """
    return (v[0], v[2], v[3])


def new_since(base, current):
    """The violations in `current` that `base` did not already contain.

    A MULTISET difference, not a set difference: two identical violations in two
    different functions must not cancel against one baseline entry, or an
    injection that duplicates an existing defect would read as having caused
    nothing.
    """
    seen = collections.Counter()
    out = []
    for v in current:
        k = violation_key(v)
        seen[k] += 1
        if seen[k] > base[k]:
            out.append(v)
    return out


def self_test(main_rs):
    original = main_rs.read_text()
    lines = original.split("\n")
    spans = fn_spans(lines)
    if INJECT_FN not in spans:
        print(f"ANCHOR FUNCTION `{INJECT_FN}` NOT FOUND -- self-test cannot run.")
        return False
    a, b = spans[INJECT_FN][0]
    brace = next(j for j in range(a, b + 1) if "{" in lines[j - 1])
    if INJECT_FN not in serving_fns(lines, spans):
        print(f"ANCHOR `{INJECT_FN}` IS NOT CLASSIFIED SERVING -- "
              "the precondition C1/C2/C4 rely on is broken; clauses unproven.")
        return False

    # The BASELINE.  This used to be an assertion -- a non-empty baseline
    # aborted the self-test -- and that was a category error worth naming,
    # because it made the instrument's own health depend on the tree being
    # finished.  The two are independent questions.  A red default run means
    # *the code* has outstanding work; a red self-test means *the checker* can
    # no longer be trusted to find it.  Coupling them means the day the checker
    # is most needed -- the tree is red -- is the day it refuses to prove
    # itself, and the cheapest way to get the self-test back is to weaken
    # whichever clause is red.
    #
    # So the baseline is recorded rather than required, and every demonstration
    # below asserts a violation that is NEW relative to it.
    print("clean tree:")
    base, acc = run(main_rs)
    base_counter = collections.Counter(violation_key(v) for v in base)
    ok = True
    print(f"  -> {len(base)} pre-existing violation(s), {len(acc)} accepted "
          f"carve-out(s)")
    if base:
        for v in sorted(base, key=lambda x: (x[1], x[0])):
            print(f"     baseline {v[0]} main.rs:{v[1]} fn {v[2]}")
        print("  This baseline is NOT the self-test's subject and does not fail "
              "it -- run without --self-test to adjudicate it.\n"
              "  Every demonstration below is judged on violations NEW relative "
              "to the list above, keyed on (clause, function, text)\n"
              "  rather than line number. A demonstration that only re-reports "
              "a baseline violation proves nothing and counts as a failure.")
    print()

    # --- C0: the scope guard must itself be shown to fire ---------------------
    # This one is demonstrated FIRST and separately, because a truncated run is
    # not a verdict about the code -- it is the absence of one.  The injection is
    # the actual hazard: a test module appearing early in the file, which hides
    # everything below it behind a clean green result.
    probe = lines[:40] + ["#[cfg(test)]", "mod early_tests {}"] + lines[40:]
    main_rs.write_text("\n".join(probe))
    v0, _ = run(main_rs, quiet=True)
    print("C0: a #[cfg(test)] block inserted near the TOP of the file "
          "(the truncation hazard)")
    if any(x[0] == "C0" for x in v0):
        hit = next(x for x in v0 if x[0] == "C0")
        print(f"  -> RED, run refused: {hit[3]}")
    else:
        print("  -> STILL GREEN -- the scope guard does not fire on a truncated "
              "file; every clean result below is unfalsifiable")
        ok = False
    main_rs.write_text(original)
    print()

    # --- C0, second half: the landmark must catch a collapsed selector -------
    # Restores the ACTUAL original defect -- an anchor on the bare typed
    # parameter, which cannot match `Extension(operator): Extension<..>`. This
    # is the injection that in-scope defect-planting is structurally incapable
    # of finding, because it corrupts the domain rather than the predicate.
    global CALLER_PARAM
    good_selector = CALLER_PARAM
    CALLER_PARAM = re.compile(r"\boperator:\s*\w*Operator")
    v_sel, _ = run(main_rs, quiet=True)
    CALLER_PARAM = good_selector
    print("C0: the ORIGINAL selector defect restored (bare typed param, blind "
          "to the axum extractor)")
    if any(x[0] == "C0" and x[2] == "<selector>" for x in v_sel):
        print("  -> RED, run refused: the landmark caught a collapsed domain "
              "that every clause would have reported clean")
    else:
        print("  -> STILL GREEN -- the landmark does not detect the very defect "
              "it was built from; denominators are decoration")
        ok = False
    print()

    # --- the carve-out's premise must be falsifiable too ---------------------
    # Provenance cannot settle whether the carve-out is entrenchment. The
    # premise can, so the premise gets a negative control like everything else.
    gl = main_rs.parents[2] / "sandbox-core" / "src" / "gateway_lima.rs"
    print("premise: give a host-scoped query a per-operator read "
          "(let _ = self.owner_uid;)")
    if not gl.exists():
        print("  -> gateway_lima.rs absent -- premise cannot be demonstrated")
        ok = False
    else:
        gl_orig = gl.read_text()
        gl_lines = gl_orig.split("\n")
        gsites = fn_spans(gl_lines).get(sorted(HOST_SCOPED_QUERIES)[0], [])
        if not gsites:
            print("  -> ANCHOR MISSING -- premise unproven")
            ok = False
        else:
            a, b = gsites[0]
            gb = next(j for j in range(a, b + 1) if "{" in gl_lines[j - 1])
            gl.write_text("\n".join(
                gl_lines[:gb] + ["        let _ = self.owner_uid;"] + gl_lines[gb:]))
            v_p, _ = run(main_rs, quiet=True)
            gl.write_text(gl_orig)
            if any("premise BROKEN" in x[3] for x in v_p):
                print("  -> RED, premise withdrawn and the site became a "
                      "VIOLATION rather than a carve-out")
            else:
                print("  -> STILL GREEN -- the premise is unfalsifiable, and "
                      "the carve-out is an allowlist after all")
                ok = False
    print()

    # --- C8: the wire op set -------------------------------------------------
    # These mutate protocol.rs, not main.rs, on the same read/mutate/run/restore
    # shape as the premise above.  Restore is unconditional and immediate: the
    # copy is a throwaway, but a demonstration that leaves a planted field
    # behind would poison every demonstration after it.
    wire = main_rs.parents[2].joinpath(*WIRE_FILE)
    if not wire.exists():
        print("C8: " + "/".join(WIRE_FILE) + " absent -- the op-set clause "
              "cannot be demonstrated, so it is not certified by this run")
        ok = False
    elif wire.read_text().count(WIRE_ENUM_ANCHOR) != 1:
        # ANCHOR NOT UNIQUE and STILL GREEN mean different things and must not
        # print the same way: this one says the demonstration never ran.
        print(f"C8: ANCHOR NOT UNIQUE -- "
              f"{wire.read_text().count(WIRE_ENUM_ANCHOR)} occurrence(s) of "
              f"{WIRE_ENUM_ANCHOR!r}; the demonstrations did not run and this "
              "clause is uncertified")
        ok = False
    else:
        w_orig = wire.read_text()
        for lbl, variant, why in WIRE_INJECTIONS:
            wire.write_text(w_orig.replace(
                WIRE_ENUM_ANCHOR, WIRE_ENUM_ANCHOR + "\n" + variant, 1))
            v_w, _ = run(main_rs, quiet=True)
            wire.write_text(w_orig)
            fresh = new_since(base_counter, v_w)
            print(f"C8: injected a wire field -- {why}")
            print(f"    {variant.strip()}")
            hit = [x for x in fresh if x[0] == "C8" and lbl in x[3]]
            if hit:
                print(f"  -> RED, C8: {hit[0][3][:100]}")
            else:
                print(f"  -> STILL GREEN -- C8 cannot see a new `{lbl}` on the "
                      "wire; that pattern is dead, not merely quiet")
                ok = False
        find, repl = WIRE_ARGV_INJECTION
        wire.write_text(w_orig.replace(find, repl, 1))
        v_w, _ = run(main_rs, quiet=True)
        wire.write_text(w_orig)
        fresh = new_since(base_counter, v_w)
        print("C8: a free function taking an argv, OUTSIDE the local rendering "
              f"fn `{WIRE_RENDER_FN}` -- a stop condition at any count")
        hit = [x for x in fresh if x[0] == "C8" and "OUTSIDE" in x[3]]
        if hit:
            print(f"  -> RED, C8 flagged at protocol.rs:{hit[0][1]} in fn "
                  f"{hit[0][2]}")
        else:
            print("  -> STILL GREEN -- argv can appear outside the rendering "
                  "fn undetected, which is pass-through on the wire")
            ok = False
    print()

    for cid, bad, why in INJECTIONS:
        want = cid.rstrip("b")
        inj = lines[:brace] + [bad] + lines[brace:]
        main_rs.write_text("\n".join(inj))
        all_v, _ = run(main_rs, quiet=True)
        fresh = new_since(base_counter, all_v)
        got = [v for v in fresh if v[0] == want]
        other = sorted({v[0] for v in fresh if v[0] != want})
        print(f"{cid}: injected into fn {INJECT_FN} -- {why}")
        print(f"    {bad.strip()[:88]}")
        if got:
            print(f"  -> RED, {want} flagged at main.rs:{got[0][1]} in fn {got[0][2]}")
        else:
            print(f"  -> STILL GREEN -- {want} cannot detect its own defect class")
            ok = False
        if other:
            print(f"  -> also tripped {other}")
        elif cid == "C4":
            print("  -> and C1/C2 stayed GREEN on a real defect: "
                  "that is what 'they measure spelling' means, shown rather than asserted")
        main_rs.write_text(original)

    # --- deletion-shaped defects ---------------------------------------------
    for cid, present, replaced, why in DELETIONS:
        if present not in original:
            print(f"\n{cid}: ANCHOR MISSING -- cannot demonstrate; clause unproven")
            ok = False
            continue
        main_rs.write_text(original.replace(present, replaced, 1))
        v2 = new_since(base_counter, run(main_rs, quiet=True)[0])
        print(f"\n{cid}: {why}")
        print(f"    deleted: {present.strip()[:88]}")
        if any(x[0] == cid for x in v2):
            hit = next(x for x in v2 if x[0] == cid)
            print(f"  -> RED, {cid} flagged fn {hit[2]} at main.rs:{hit[1]}")
        else:
            print(f"  -> STILL GREEN -- {cid} cannot detect its own defect class")
            ok = False
        main_rs.write_text(original)

    # --- negative control for the C4 carve-out --------------------------------
    # A carve-out that cannot fail is an allowlist wearing a predicate's
    # clothes.  Take each accepted site and give its binding one use outside
    # HOST_SCOPED_QUERIES; C4 must stop accepting it and start flagging it.
    for cid, lno, fn, site, why in acc:
        bind = re.search(r"`([A-Za-z0-9_]+)`", why).group(1)
        inj = lines[:lno] + [f"    let _ = {bind}.start_gateway();"] + lines[lno:]
        main_rs.write_text("\n".join(inj))
        v2, a2 = run(main_rs, quiet=True)
        v2 = new_since(base_counter, v2)
        print(f"\ncarve-out negative control at main.rs:{lno} (fn {fn}):")
        print(f"    gave `{bind}` a non-host-scoped use -- let _ = {bind}.start_gateway();")
        if any(x[0] == "C4" for x in v2) and not a2:
            print("  -> RED, carve-out withdrawn and C4 flagged it. "
                  "The exception is earned per-site, not granted.")
        else:
            print(f"  -> STILL ACCEPTED ({len(v2)} viol, {len(a2)} accepted) -- "
                  "the carve-out is unfalsifiable and is functioning as an allowlist")
            ok = False
        main_rs.write_text(original)

    print()
    ok = non_caller_controls(main_rs, ok, base_counter)

    # The parenthetical describes what a PASS means, so it must not be printed
    # on a FAIL -- "FAIL (every clause demonstrated RED)" reads as a success
    # with an unlucky verdict, which is exactly the misreading this whole file
    # exists to prevent.  For the same reason it must not claim the tree was
    # clean when it was not: a PASS here is a statement about the INSTRUMENT,
    # and printing "clean tree GREEN" over a red baseline would launder the
    # code's outstanding work through the checker's own good health.
    if ok:
        print("\nself-test: PASS (every clause demonstrated RED, every "
              "carve-out shown withdrawable)")
        if base:
            print(f"  The instrument works. The TREE does not: {len(base)} "
                  "violation(s) were already present before any injection,\n"
                  "  listed at the top of this run. This PASS says nothing "
                  "about them -- run without --self-test to see them "
                  "adjudicated.")
        else:
            print("  Baseline was clean, so a green default run on this "
                  "revision means what it says.")
    else:
        print("\nself-test: FAIL -- at least one demonstration above did not go "
              "RED.\n  Read the lines marked STILL GREEN / STILL ACCEPTED / "
              "ANCHOR NOT UNIQUE.\n  Until they are resolved, a clean run of "
              "this checker cannot be told apart from a dead clause, so treat "
              "a PASS from the default mode as unproven.")
    return ok


def default_repo_root():
    """The repository this file lives in.

    Asked of git from the script's own directory, so a checkout anywhere works
    and a copy of this file outside a repo fails loudly instead of silently
    grading somebody else's tree.
    """
    here = pathlib.Path(__file__).resolve().parent
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=here,
                             capture_output=True, text=True, check=True)
        return top.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return str(here.parent)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Check the gateway-owner uid invariant. Defaults to the "
                    "working tree; see --rev to audit a committed revision.")
    ap.add_argument("--rev", metavar="COMMITISH",
                    help="check a committed revision instead of the working "
                         "tree, via `git archive`. Use this to re-audit a "
                         "specific commit; the gate wants the default.")
    ap.add_argument("--tree", metavar="DIR",
                    help="check an already-extracted workspace root.")
    ap.add_argument("--repo-root", default=default_repo_root(), metavar="DIR",
                    help="repository to read (default: the one this file is in).")
    ap.add_argument("--self-test", action="store_true",
                    help="inject a real contract violation for every clause and "
                         "require each to go RED. Run this on the same revision "
                         "as the clean run -- a clean run whose self-test was "
                         "not run beside it certifies nothing.")
    a = ap.parse_args()
    REPO = a.repo_root

    # Source selection, and the provenance line that says which one was read.
    if a.tree:
        root = pathlib.Path(a.tree)
        print(f"  source: --tree {root}")
    elif a.rev:
        root = extract_rev(a.rev)
        print(f"  source: --rev {a.rev} (committed; the working tree is NOT read)")
    else:
        root, copied = snapshot_worktree()
        head, dirty = worktree_provenance()
        print(f"  source: working tree at {REPO} -- {copied} Rust file(s), "
              f"HEAD {head}, {len(dirty)} uncommitted change(s) under sandboxd/"
              + (f": {', '.join(dirty)}" if dirty else ""))

    # Checked before anything touches the tree, so the refusal does not depend
    # on the layout underneath the root being what we expected.
    if a.self_test:
        refuse_if_inside_repo(root)

    main_rs = root / "sandboxd" / "sandboxd" / "src" / "main.rs"
    if not main_rs.exists():
        sys.exit(f"no such file: {main_rs} -- wrong --repo-root, --tree or --rev?")

    if a.self_test:
        sys.exit(0 if self_test(main_rs) else 1)
    v, acc = run(main_rs)
    print(f"\n{'PASS -- no violations' if not v else f'FAIL -- {len(v)} violations'}"
          f"{f'; {len(acc)} accepted carve-out(s), listed above' if acc else ''}")
    print("NOTE: a clean result is only meaningful if --self-test passes on the "
          "same revision, and only as wide as the denominators above.")
    sys.exit(0 if not v else 1)
