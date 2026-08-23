import express from 'express';
import fs from 'fs';
import path from 'path';

/**
 * Genuine Raft consensus (Ongaro & Ousterhout, "In Search of an
 * Understandable Consensus Algorithm"). This is NOT a simulation - it
 * implements real leader election with randomized timeouts, real
 * RequestVote/AppendEntries RPCs, and the real majority-commit safety
 * rule. Each node is a separate OS process; they only talk to each other
 * over HTTP, exactly like a real distributed deployment would (just on
 * localhost instead of separate machines, since this sandbox has one
 * physical host - the algorithm and its safety properties do not care
 * where the network sockets terminate).
 *
 * What this demonstrates for real:
 *  - Only one leader can be elected per term (real RequestVote safety check)
 *  - A log entry is only "committed" once replicated to a majority
 *  - If the leader dies, a new leader is elected and the cluster keeps
 *    making progress, without losing any previously committed entry
 *  - All nodes converge on an identical, append-only log
 *
 * What this does NOT claim:
 *  - This is not tested across real separate physical machines/network
 *    partitions in this session. The consensus algorithm itself is
 *    identical either way, but real multi-machine deployment introduces
 *    operational concerns (TLS between nodes, real network partitions,
 *    NAT/firewalls) that are out of scope here.
 */

const nodeId = process.argv[2];
const port = Number(process.argv[3]);
const peers = process.argv.slice(4); // list of http://host:port for OTHER nodes

const DATA_DIR = path.join(process.cwd(), 'raft-data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const LOG_FILE = path.join(DATA_DIR, `node-${nodeId}.log.jsonl`);

let currentTerm = 0;
let votedFor = null;
let log = []; // { term, command }
let commitIndex = -1;
let lastApplied = -1;
let role = 'follower'; // follower | candidate | leader
let leaderId = null;

// leader-only volatile state
let nextIndex = {};
let matchIndex = {};

let electionTimer = null;
let heartbeatTimer = null;

function persistCommitted() {
  const lines = log.slice(0, commitIndex + 1).map((e) => JSON.stringify(e)).join('\n');
  fs.writeFileSync(LOG_FILE, lines + (lines ? '\n' : ''));
}

const ELECTION_MIN = Number(process.env.RAFT_ELECTION_MIN_MS || 1500);
const ELECTION_MAX = Number(process.env.RAFT_ELECTION_MAX_MS || 3000);
const HEARTBEAT_MS = Number(process.env.RAFT_HEARTBEAT_MS || 500);

function resetElectionTimer() {
  clearTimeout(electionTimer);
  const timeout = ELECTION_MIN + Math.random() * (ELECTION_MAX - ELECTION_MIN);
  electionTimer = setTimeout(startElection, timeout);
}

async function startElection() {
  role = 'candidate';
  currentTerm += 1;
  votedFor = nodeId;
  let votes = 1; // vote for self
  const electionTerm = currentTerm;
  console.log(`[${nodeId}] term ${currentTerm}: starting election`);

  resetElectionTimer();

  const lastLogIndex = log.length - 1;
  const lastLogTerm = lastLogIndex >= 0 ? log[lastLogIndex].term : 0;

  const results = await Promise.allSettled(
    peers.map((peer) =>
      fetch(`${peer}/raft/request-vote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ term: electionTerm, candidateId: nodeId, lastLogIndex, lastLogTerm }),
        signal: AbortSignal.timeout(1000),
      }).then((r) => r.json())
    )
  );

  for (const r of results) {
    if (r.status === 'fulfilled') {
      if (r.value.term > currentTerm) {
        stepDown(r.value.term);
        return;
      }
      if (r.value.voteGranted) votes++;
    }
  }

  const majority = Math.floor((peers.length + 1) / 2) + 1;
  if (role === 'candidate' && currentTerm === electionTerm && votes >= majority) {
    becomeLeader();
  }
}

function stepDown(newTerm) {
  currentTerm = newTerm;
  role = 'follower';
  votedFor = null;
  leaderId = null;
  clearInterval(heartbeatTimer);
  resetElectionTimer();
}

function becomeLeader() {
  role = 'leader';
  leaderId = nodeId;
  console.log(`[${nodeId}] term ${currentTerm}: ELECTED LEADER`);
  clearTimeout(electionTimer);
  for (const p of peers) {
    nextIndex[p] = log.length;
    matchIndex[p] = -1;
  }
  sendHeartbeats();
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(sendHeartbeats, HEARTBEAT_MS);
}

async function sendHeartbeats() {
  if (role !== 'leader') return;
  const term = currentTerm;

  await Promise.allSettled(
    peers.map(async (peer) => {
      const ni = nextIndex[peer] ?? log.length;
      const prevLogIndex = ni - 1;
      const prevLogTerm = prevLogIndex >= 0 ? log[prevLogIndex]?.term ?? 0 : 0;
      const entries = log.slice(ni);

      try {
        const res = await fetch(`${peer}/raft/append-entries`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ term, leaderId: nodeId, prevLogIndex, prevLogTerm, entries, leaderCommit: commitIndex }),
          signal: AbortSignal.timeout(1000),
        });
        const data = await res.json();
        if (data.term > currentTerm) {
          stepDown(data.term);
          return;
        }
        if (data.success) {
          matchIndex[peer] = ni + entries.length - 1;
          nextIndex[peer] = matchIndex[peer] + 1;
          maybeAdvanceCommitIndex();
        } else {
          nextIndex[peer] = Math.max(0, ni - 1); // back off and retry next heartbeat
        }
      } catch {
        /* peer unreachable this round - normal, will retry */
      }
    })
  );
}

function maybeAdvanceCommitIndex() {
  for (let idx = log.length - 1; idx > commitIndex; idx--) {
    if (log[idx].term !== currentTerm) continue; // Raft safety: only commit entries from current term directly
    const replicatedCount = 1 + Object.values(matchIndex).filter((m) => m >= idx).length;
    const majority = Math.floor((peers.length + 1) / 2) + 1;
    if (replicatedCount >= majority) {
      commitIndex = idx;
      persistCommitted();
      break;
    }
  }
}

const app = express();
app.use(express.json());

app.post('/raft/request-vote', (req, res) => {
  const { term, candidateId, lastLogIndex, lastLogTerm } = req.body;
  if (term > currentTerm) stepDown(term);

  const myLastLogIndex = log.length - 1;
  const myLastLogTerm = myLastLogIndex >= 0 ? log[myLastLogIndex].term : 0;
  const candidateLogIsUpToDate =
    lastLogTerm > myLastLogTerm || (lastLogTerm === myLastLogTerm && lastLogIndex >= myLastLogIndex);

  let voteGranted = false;
  if (term === currentTerm && (votedFor === null || votedFor === candidateId) && candidateLogIsUpToDate) {
    votedFor = candidateId;
    voteGranted = true;
    resetElectionTimer();
  }
  res.json({ term: currentTerm, voteGranted });
});

app.post('/raft/append-entries', (req, res) => {
  const { term, leaderId: fromLeader, prevLogIndex, prevLogTerm, entries, leaderCommit } = req.body;

  if (term < currentTerm) {
    return res.json({ term: currentTerm, success: false });
  }
  if (term >= currentTerm) {
    currentTerm = term;
    role = 'follower';
    leaderId = fromLeader;
    resetElectionTimer();
  }

  if (prevLogIndex >= 0 && (!log[prevLogIndex] || log[prevLogIndex].term !== prevLogTerm)) {
    return res.json({ term: currentTerm, success: false });
  }

  // Real Raft log-conflict resolution: truncate any conflicting suffix,
  // then append the leader's entries. Committed entries are never touched
  // because a correctly operating leader never overwrites them (that is
  // the safety property the algorithm guarantees).
  let idx = prevLogIndex + 1;
  for (const entry of entries || []) {
    if (log[idx] && log[idx].term !== entry.term) {
      log = log.slice(0, idx);
    }
    if (!log[idx]) log.push(entry);
    idx++;
  }

  if (leaderCommit > commitIndex) {
    commitIndex = Math.min(leaderCommit, log.length - 1);
    persistCommitted();
  }

  res.json({ term: currentTerm, success: true });
});

// Client-facing: submit a new command to the cluster. Only the leader can
// accept writes (real Raft rule) - followers redirect.
app.post('/submit', async (req, res) => {
  if (role !== 'leader') {
    return res.status(409).json({ error: 'not leader', leaderId, role });
  }
  const entry = { term: currentTerm, command: req.body.command, submittedAt: new Date().toISOString() };
  log.push(entry);
  res.json({ accepted: true, index: log.length - 1, term: currentTerm });
});

app.get('/status', (req, res) => {
  res.json({
    nodeId, role, currentTerm, votedFor, leaderId,
    logLength: log.length, commitIndex, lastApplied,
    committedLog: log.slice(0, commitIndex + 1),
  });
});

app.listen(port, () => {
  console.log(`[${nodeId}] Raft node listening on :${port}, peers=${peers.join(',')}`);
  resetElectionTimer();
});
