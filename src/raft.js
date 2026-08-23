import express from 'express';
import crypto from 'crypto';

/**
 * Embeddable Raft node, mountable inside an existing Express app.
 *
 * SECURITY: every RequestVote/AppendEntries RPC is HMAC-signed with a
 * shared cluster secret (CLUSTER_SECRET). A node without the correct
 * secret cannot forge votes or log entries - this closes the "node
 * impersonation" gap flagged in THREAT-MODEL.md and by independent
 * review (a node could otherwise claim any nodeId and inject log
 * entries). This is not a substitute for mTLS (which would also
 * encrypt the traffic, not just authenticate it - see README for the
 * honest scope note on this), but it does provide real message-origin
 * authentication with no additional infrastructure required.
 *
 * Design mirrors real HashiCorp Vault "integrated storage" HA:
 *  - Raft replicates the KMS STATE MACHINE (key metadata, already-encrypted
 *    secret records, vault init metadata/verifier hash) across nodes.
 *  - Raft NEVER carries the master key or any plaintext. The master key
 *    only ever exists in a given node's RAM after an operator submits
 *    Shamir shares to THAT node directly (same as real Vault: you must
 *    unseal every replica individually with the same unseal keys).
 *  - Only the current leader accepts writes; followers respond with the
 *    current leader's id so the caller can retry there (same pattern
 *    etcd/Raft-based systems use).
 */
export function createRaftNode({ nodeId, peerUrls, clusterSecret, electionMinMs = 1500, electionMaxMs = 3000, heartbeatMs = 500, onApply }) {
  if (!clusterSecret) {
    throw new Error('createRaftNode requires clusterSecret - Raft RPCs must be HMAC-signed. Set CLUSTER_SECRET env var.');
  }

  function sign(payload) {
    return crypto.createHmac('sha256', clusterSecret).update(JSON.stringify(payload)).digest('hex');
  }
  function verify(payload, signature) {
    if (!signature) return false;
    const expected = sign(payload);
    // both must be equal length for timingSafeEqual - guard against
    // a malformed/short signature crashing the comparison
    if (expected.length !== signature.length) return false;
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  }

  let currentTerm = 0;
  let votedFor = null;
  let log = []; // { term, command }
  let commitIndex = -1;
  let lastApplied = -1;
  let role = 'follower';
  let leaderId = null;
  let nextIndex = {};
  let matchIndex = {};
  let electionTimer = null;
  let heartbeatTimer = null;
  const pending = new Map(); // commandId -> { resolve, reject }

  function resetElectionTimer() {
    clearTimeout(electionTimer);
    const t = electionMinMs + Math.random() * (electionMaxMs - electionMinMs);
    electionTimer = setTimeout(startElection, t);
  }

  async function startElection() {
    role = 'candidate';
    currentTerm += 1;
    votedFor = nodeId;
    let votes = 1;
    const electionTerm = currentTerm;
    resetElectionTimer();

    const lastLogIndex = log.length - 1;
    const lastLogTerm = lastLogIndex >= 0 ? log[lastLogIndex].term : 0;

    const results = await Promise.allSettled(
      peerUrls.map((peer) => {
        const payload = { term: electionTerm, candidateId: nodeId, lastLogIndex, lastLogTerm };
        return fetch(`${peer}/raft/request-vote`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...payload, signature: sign(payload) }),
          signal: AbortSignal.timeout(1000),
        }).then((r) => r.json());
      })
    );
    for (const r of results) {
      if (r.status === 'fulfilled') {
        if (r.value.term > currentTerm) { stepDown(r.value.term); return; }
        if (r.value.voteGranted) votes++;
      }
    }
    const majority = Math.floor((peerUrls.length + 1) / 2) + 1;
    if (role === 'candidate' && currentTerm === electionTerm && votes >= majority) becomeLeader();
  }

  function stepDown(newTerm) {
    currentTerm = newTerm;
    role = 'follower';
    votedFor = null;
    leaderId = null;
    clearInterval(heartbeatTimer);
    resetElectionTimer();
    for (const [, p] of pending) p.reject(new Error('stepped down before commit'));
    pending.clear();
  }

  function becomeLeader() {
    role = 'leader';
    leaderId = nodeId;
    clearTimeout(electionTimer);
    for (const p of peerUrls) { nextIndex[p] = log.length; matchIndex[p] = -1; }
    sendHeartbeats();
    clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(sendHeartbeats, heartbeatMs);
  }

  async function sendHeartbeats() {
    if (role !== 'leader') return;
    const term = currentTerm;
    await Promise.allSettled(peerUrls.map(async (peer) => {
      const ni = nextIndex[peer] ?? log.length;
      const prevLogIndex = ni - 1;
      const prevLogTerm = prevLogIndex >= 0 ? log[prevLogIndex]?.term ?? 0 : 0;
      const entries = log.slice(ni);
      try {
        const payload = { term, leaderId: nodeId, prevLogIndex, prevLogTerm, entries, leaderCommit: commitIndex };
        const res = await fetch(`${peer}/raft/append-entries`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...payload, signature: sign(payload) }),
          signal: AbortSignal.timeout(1000),
        });
        const data = await res.json();
        if (data.term > currentTerm) { stepDown(data.term); return; }
        if (data.success) {
          matchIndex[peer] = ni + entries.length - 1;
          nextIndex[peer] = matchIndex[peer] + 1;
          await maybeAdvanceCommitIndex();
        } else {
          nextIndex[peer] = Math.max(0, ni - 1);
        }
      } catch { /* peer unreachable this round */ }
    }));
  }

  async function maybeAdvanceCommitIndex() {
    for (let idx = log.length - 1; idx > commitIndex; idx--) {
      if (log[idx].term !== currentTerm) continue;
      const replicated = 1 + Object.values(matchIndex).filter((m) => m >= idx).length;
      const majority = Math.floor((peerUrls.length + 1) / 2) + 1;
      if (replicated >= majority) {
        commitIndex = idx;
        await applyCommitted();
        break;
      }
    }
  }

  async function applyCommitted() {
    while (lastApplied < commitIndex) {
      lastApplied++;
      const entry = log[lastApplied];
      let result, error;
      try { result = await onApply(entry.command); }
      catch (e) { error = e; }
      const waiter = pending.get(entry.command.commandId);
      if (waiter) {
        error ? waiter.reject(error) : waiter.resolve(result);
        pending.delete(entry.command.commandId);
      }
    }
  }

  function propose(command) {
    return new Promise((resolve, reject) => {
      if (role !== 'leader') return reject(Object.assign(new Error('not leader'), { notLeader: true, leaderId }));
      command.commandId = crypto.randomUUID();
      log.push({ term: currentTerm, command });
      pending.set(command.commandId, { resolve, reject });
      sendHeartbeats();
      setTimeout(() => {
        if (pending.has(command.commandId)) {
          pending.delete(command.commandId);
          reject(new Error('commit timeout - lost leadership or cluster unavailable'));
        }
      }, 5000);
    });
  }

  const router = express.Router();

  router.post('/raft/request-vote', (req, res) => {
    const { term, candidateId, lastLogIndex, lastLogTerm, signature } = req.body;
    const payload = { term, candidateId, lastLogIndex, lastLogTerm };
    if (!verify(payload, signature)) {
      return res.status(401).json({ error: 'Invalid or missing HMAC signature - request rejected before any state change' });
    }
    if (term > currentTerm) stepDown(term);
    const myLastLogIndex = log.length - 1;
    const myLastLogTerm = myLastLogIndex >= 0 ? log[myLastLogIndex].term : 0;
    const upToDate = lastLogTerm > myLastLogTerm || (lastLogTerm === myLastLogTerm && lastLogIndex >= myLastLogIndex);
    let voteGranted = false;
    if (term === currentTerm && (votedFor === null || votedFor === candidateId) && upToDate) {
      votedFor = candidateId;
      voteGranted = true;
      resetElectionTimer();
    }
    res.json({ term: currentTerm, voteGranted });
  });

  router.post('/raft/append-entries', async (req, res) => {
    const { term, leaderId: fromLeader, prevLogIndex, prevLogTerm, entries, leaderCommit, signature } = req.body;
    const payload = { term, leaderId: fromLeader, prevLogIndex, prevLogTerm, entries, leaderCommit };
    if (!verify(payload, signature)) {
      return res.status(401).json({ error: 'Invalid or missing HMAC signature - request rejected before any state change' });
    }
    if (term < currentTerm) return res.json({ term: currentTerm, success: false });
    if (term >= currentTerm) {
      currentTerm = term; role = 'follower'; leaderId = fromLeader; resetElectionTimer();
    }
    if (prevLogIndex >= 0 && (!log[prevLogIndex] || log[prevLogIndex].term !== prevLogTerm)) {
      return res.json({ term: currentTerm, success: false });
    }
    let idx = prevLogIndex + 1;
    for (const entry of entries || []) {
      if (log[idx] && log[idx].term !== entry.term) log = log.slice(0, idx);
      if (!log[idx]) log.push(entry);
      idx++;
    }
    if (leaderCommit > commitIndex) {
      commitIndex = Math.min(leaderCommit, log.length - 1);
      await applyCommitted();
    }
    res.json({ term: currentTerm, success: true });
  });

  router.get('/raft/status', (req, res) => {
    res.json({ nodeId, role, currentTerm, leaderId, logLength: log.length, commitIndex });
  });

  resetElectionTimer();

  return {
    router,
    propose,
    isLeader: () => role === 'leader',
    getLeaderId: () => leaderId,
    getStatus: () => ({ nodeId, role, currentTerm, leaderId, logLength: log.length, commitIndex }),
  };
}
