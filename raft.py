import certifi
import grpc
import random
import threading
import time
from concurrent import futures
from enum import Enum
import logging

import raft_pb2
import raft_pb2_grpc
from config import Config  # Assumed to provide server_id, servers, db_path, etc.
from database import DatabaseManager  # Your SQL-backed DatabaseManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define node states using standard Enum
class NodeState(Enum):
    FOLLOWER = 1
    CANDIDATE = 2
    LEADER = 3

# Raft Node using SQL database for persistence and standard (non-reentrant) locks
class RaftNode:
    def __init__(self, server_id: str, config: Config, db: DatabaseManager):
        self.id = server_id
        self.config = config
        self.db = db

        # Volatile state
        self.state = NodeState.FOLLOWER
        self.current_term = self.db.get_raft_state('current_term') or 0
        self.voted_for = self.db.get_raft_state('voted_for')
        self.leader_id = None
        self.last_heartbeat = 0

        # Use non-reentrant locks
        self.state_lock = threading.RLock()
        self.votes_lock = threading.RLock()

        # Set up RPC stubs for peers (skip self)
        self.peer_addresses = {s.id: s.address for s in config.server_list if s.id != self.id}
        print(self.peer_addresses)
        self.stubs = {}
        with open(certifi.where(), "rb") as f:
            trusted_certs = f.read()
        # Create secure channel credentials using the trusted certificates
        credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)
        for peer_id, addr in self.peer_addresses.items():
            channel = grpc.secure_channel(addr, credentials=credentials)
            self.stubs[peer_id] = raft_pb2_grpc.RaftServiceStub(channel)

        # Election timer: if single server, become leader immediately.
        self.election_reset_event = threading.Event()
        self.running = True
        if len(self.config.servers) == 1:
            logger.info("Single server mode detected, becoming leader immediately")
            with self.state_lock:
                self.state = NodeState.LEADER
                self.leader_id = self.id
        else:
            self.election_thread = threading.Thread(target=self.election_timeout_loop, daemon=True)
            self.election_thread.start()

        # Heartbeat thread (only active when leader)
        self.heartbeat_thread = None

    def _get_election_timeout(self) -> float:
        """Return election timeout in seconds."""
        return random.randint(self.config.election_timeout_min, self.config.election_timeout_max) / 1000.0

    def election_timeout_loop(self):
        while self.running:
            timeout = self._get_election_timeout()
            # Wait for either a heartbeat (or election reset) or timeout
            if self.election_reset_event.wait(timeout):
                self.election_reset_event.clear()
                continue
            # Timeout expired; start an election
            self.start_election()

    def start_election(self):
        # Acquire state_lock only briefly for state update
        with self.state_lock:
            if self.state == NodeState.LEADER:
                return  # Already leader
            self.state = NodeState.CANDIDATE
            self.current_term += 1
            self.voted_for = self.id
            self.db.save_raft_state('current_term', self.current_term)
            self.db.save_raft_state('voted_for', self.id)
            term = self.current_term
        logger.info(f"Node {self.id} starting election for term {term}")

        # Get last log info from SQL database
        last_log_index, last_log_term = self.db.get_last_log_entry()
        request = raft_pb2.RequestVoteRequest(
            term=term,
            candidate_id=self.id,
            last_log_index=last_log_index,
            last_log_term=last_log_term
        )
        votes_granted = 1  # Vote for self
        for peer_id, stub in self.stubs.items():
            try:
                response = stub.RequestVote(request, timeout=0.5)
                logger.info(f"Node {self.id} received {response.vote_granted}")
                if response.vote_granted:
                    # logger.info(f"Node {self.id} received vote from {peer_id}")
                    with self.votes_lock:
                        votes_granted += 1
            except grpc.RpcError as e:
                logger.warning(f"RequestVote RPC to {peer_id} failed: {e}")

        if votes_granted > (len(self.config.servers) // 2):
            self.become_leader()
        else:
            with self.state_lock:
                self.state = NodeState.FOLLOWER
            logger.info(f"Node {self.id} lost election for term {term}")
            self.election_reset_event.set()  # Restart election timer

    def become_leader(self):
        with self.state_lock:
            self.state = NodeState.LEADER
            self.leader_id = self.id
        logger.info(f"Node {self.id} became leader for term {self.current_term}")
        if self.heartbeat_thread is None or not self.heartbeat_thread.is_alive():
            self.heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()

    def heartbeat_loop(self):
        while self.running and self.state == NodeState.LEADER:
            self.send_heartbeats()
            time.sleep(self.config.heartbeat_interval / 1000.0)

    def send_heartbeats(self):
        request = raft_pb2.AppendEntriesRequest(
            term=self.current_term,
            leader_id=self.id,
            prev_log_index=0,  # Simplified: dummy values for heartbeat
            prev_log_term=0,
            entries=[],       # Empty entries signify heartbeat
            leader_commit=0
        )
        for peer_id, stub in self.stubs.items():
            try:
                response = stub.AppendEntries(request, timeout=0.5)
                if response.term > self.current_term:
                    # Call step_down outside any existing lock context
                    self.step_down(response.term)
            except grpc.RpcError as e:
                logger.warning(f"Heartbeat RPC to {peer_id} failed: {e}")

    def step_down(self, new_term: int):
        # Acquire lock in step_down and update state without calling further locked functions
        with self.state_lock:
            logger.info(f"Node {self.id} stepping down; new term {new_term}")
            self.state = NodeState.FOLLOWER
            self.current_term = new_term
            self.voted_for = None
            self.db.save_raft_state('current_term', self.current_term)
            self.db.save_raft_state('voted_for', None)
            self.leader_id = None
        self.election_reset_event.set()

    def handle_heartbeat(self, term: int, leader_id: str):
        # Inline update rather than calling other functions
        with self.state_lock:
            if term >= self.current_term:
                self.current_term = term
                self.leader_id = leader_id
                self.state = NodeState.FOLLOWER
                self.db.save_raft_state('current_term', self.current_term)
                self.db.save_raft_state('voted_for', None)
        self.election_reset_event.set()

    def replicate_log(self, operation_type: str, data: bytes) -> bool:
        # Only leader can replicate.
        with self.state_lock:
            if self.state != NodeState.LEADER:
                logger.warning("Cannot replicate log: not a leader")
                return False
            # Append the log entry to the leader's log.
            index = self.db.append_raft_log(self.current_term, operation_type, data)
            logger.info(f"Appended log entry {index} (term {self.current_term}, op: {operation_type})")
        success_count = 1  # Leader counts as replicated.

        # Prepare necessary fields for AppendEntries.
        prev_index = index - 1
        if prev_index > 0:
            prev_entry = self.db.get_raft_log_entry(prev_index)
            prev_term = prev_entry['term'] if prev_entry else 0
        else:
            prev_term = 0

        # Create a LogEntry message that encapsulates this operation.
        log_entry = raft_pb2.LogEntry(
            term=self.current_term,
            index=index,
            data=data,
            operation_type=operation_type
        )

        # Create an AppendEntries request to replicate this log entry.
        ae_request = raft_pb2.AppendEntriesRequest(
            term=self.current_term,
            leader_id=self.id,
            prev_log_index=prev_index,
            prev_log_term=prev_term,
            entries=[log_entry],
            leader_commit=0
        )

        # First, replicate using AppendEntries.
        def replicate_to_peer(peer_id, stub):
            nonlocal success_count
            try:
                response = stub.AppendEntries(ae_request, timeout=0.5)
                if response.success:
                    with self.votes_lock:
                        success_count += 1
                elif response.term > self.current_term:
                    self.step_down(response.term)
            except grpc.RpcError as e:
                logger.warning(f"AppendEntries RPC to {peer_id} failed: {e}")

        threads = []
        for peer_id, stub in self.stubs.items():
            t = threading.Thread(target=replicate_to_peer, args=(peer_id, stub))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        majority = success_count > (len(self.config.servers) // 2)
        logger.info(f"AppendEntries replication result: {success_count}/{len(self.config.servers)}")
        if not majority:
            return False

        # Now, explicitly call ReplicateLog so that followers update their SQL state.
        def call_replicate(peer_id, stub):
            try:
                # Pass the log entry message to the follower.
                response = stub.ReplicateLog(log_entry, timeout=0.5)
                return response.success
            except grpc.RpcError as e:
                logger.warning(f"ReplicateLog RPC to {peer_id} failed: {e}")
                return False

        replicate_results = []
        threads = []

        def replicate_and_collect(peer_id, stub):
            res = call_replicate(peer_id, stub)
            replicate_results.append(res)

        for peer_id, stub in self.stubs.items():
            t = threading.Thread(target=replicate_and_collect, args=(peer_id, stub))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        total_success = sum(1 for r in replicate_results if r) + 1  # +1 for leader.
        majority_apply = total_success > (len(self.config.servers) // 2)
        logger.info(f"ReplicateLog result: {total_success}/{len(self.config.servers)}; majority: {majority_apply}")
        return majority_apply

# RaftService implements the gRPC interface
class RaftService(raft_pb2_grpc.RaftServiceServicer):
    def __init__(self, node: RaftNode):
        self.node = node
    
    def ReplicateLog(self, request, context):
        """
        Corrected ReplicateLog handler:
        - Ensures the request's term is acceptable.
        - Appends the log entry to the follower’s log.
        - Applies the operation to the local SQL database.
        """
        with self.node.state_lock:
            if request.term < self.node.current_term:
                return raft_pb2.ReplicationResponse(
                    success=False,
                    error_message="Term too low"
                )
            if request.term > self.node.current_term:
                # Update state for new term
                self.node.current_term = request.term
                self.node.voted_for = None
                self.node.state = NodeState.FOLLOWER
                self.node.db.save_raft_state('current_term', self.node.current_term)
                self.node.db.save_raft_state('voted_for', None)
                self.node.leader_id = request.leader_id

        try:
            # Append the log entry to the local Raft log.
            idx = self.node.db.append_raft_log(request.term, request.operation_type, request.data)
            logger.info(f"ReplicateLog: Appended log entry {idx} (term {request.term}, op: {request.operation_type})")
            
            # Apply the operation to update the local state machine.
            self.apply_log_entry(request)
        except Exception as e:
            logger.exception("Error applying replicated log entry")
            return raft_pb2.ReplicationResponse(
                success=False,
                error_message=str(e)
            )
        return raft_pb2.ReplicationResponse(success=True)

    def apply_log_entry(self, entry):
        """
        Decodes and applies the operation in the log entry to the local SQL database.
        """
        op = entry.operation_type
        try:
            if op == "CREATE_USER":
                # Expect data: "username:password_hash"
                data_decoded = entry.data.decode()
                username, password_hash = data_decoded.split(":", 1)
                logger.info(f"Applying CREATE_USER for {username}")
                self.node.db.create_user(username, password_hash)
            elif op == "DELETE_USER":
                # Data is the username.
                username = entry.data.decode()
                logger.info(f"Applying DELETE_USER for {username}")
                self.node.db.delete_user(username)
            elif op == "SAVE_MESSAGE":
                # Expect data: "message_id|sender|recipient|content|timestamp"
                data_decoded = entry.data.decode()
                parts = data_decoded.split("|")
                if len(parts) == 5:
                    message_id, sender, recipient, content, timestamp_str = parts
                    timestamp = int(timestamp_str)
                    logger.info(f"Applying SAVE_MESSAGE from {sender} to {recipient}")
                    self.node.db.save_message(message_id, sender, recipient, content, timestamp)
                else:
                    raise ValueError("Invalid SAVE_MESSAGE data format")
            elif op == "DELETE_MESSAGES":
                # Expect data: "username:msgid1,msgid2,..."
                data_decoded = entry.data.decode()
                username, msgids_str = data_decoded.split(":", 1)
                msg_ids = msgids_str.split(",")
                logger.info(f"Applying DELETE_MESSAGES for {username}")
                self.node.db.delete_messages(msg_ids)
            elif op == "CREATE_SESSION":
                # Expect data: "session_token:username"
                data_decoded = entry.data.decode()
                session_token, username = data_decoded.split(":", 1)
                logger.info(f"Applying CREATE_SESSION for {username} with token {session_token}")
                # Optionally, you might want to store an expiration; here we use default 86400 sec.
                self.node.db.create_session(session_token, username)
            else:
                logger.error(f"Unknown operation type: {op}")
                raise ValueError("Unknown operation type")
        except Exception as e:
            logger.exception("Error applying log entry")
            raise e


    def RequestVote(self, request, context):
        with self.node.state_lock:
            # Reject if the candidate's term is lower than our current term.
            if request.term < self.node.current_term:
                logger.info(f"Rejecting vote: request.term ({request.term}) < current_term ({self.node.current_term})")
                return raft_pb2.RequestVoteResponse(
                    term=self.node.current_term,
                    vote_granted=False
                )
            
            # If the candidate's term is greater, update our state.
            if request.term > self.node.current_term:
                logger.info(f"New term detected: {request.term}. Resetting voted_for and updating state.")
                self.node.current_term = request.term
                self.node.voted_for = None
                self.node.state = NodeState.FOLLOWER
                self.node.db.save_raft_state('current_term', self.node.current_term)
                self.node.db.save_raft_state('voted_for', None)
            
            # Vote if we haven't voted for anyone in this term or already voted for this candidate.
            if self.node.voted_for is None or self.node.voted_for == request.candidate_id:
                last_index, last_term = self.node.db.get_last_log_entry()
                # Candidate's log is considered up-to-date if its last log term is greater,
                # or if equal and its index is at least as large as ours.
                if (request.last_log_term > last_term or
                    (request.last_log_term == last_term and request.last_log_index >= last_index)):
                    logger.info(f"Granting vote to candidate {request.candidate_id} for term {self.node.current_term}")
                    self.node.voted_for = request.candidate_id
                    self.node.db.save_raft_state('voted_for', request.candidate_id)
                    return raft_pb2.RequestVoteResponse(
                        term=self.node.current_term,
                        vote_granted=True
                    )
                else:
                    logger.info(f"Rejecting vote: candidate {request.candidate_id} log not up-to-date "
                                f"(candidate: term {request.last_log_term}, index {request.last_log_index}; "
                                f"local: term {last_term}, index {last_index})")
            else:
                logger.info(f"Already voted for {self.node.voted_for} in term {self.node.current_term}")
                
        return raft_pb2.RequestVoteResponse(
            term=self.node.current_term,
            vote_granted=False
        )

    def AppendEntries(self, request, context):
        with self.node.state_lock:
            if request.term < self.node.current_term:
                return raft_pb2.AppendEntriesResponse(
                    term=self.node.current_term,
                    success=False
                )
            if request.term > self.node.current_term:
                # Inline update instead of calling step_down()
                self.node.current_term = request.term
                self.node.voted_for = None
                self.node.state = NodeState.FOLLOWER
                self.node.db.save_raft_state('current_term', self.node.current_term)
                self.node.db.save_raft_state('voted_for', None)
                self.node.leader_id = request.leader_id
            # Handle heartbeat: update state and reset election timeout
            self.node.handle_heartbeat(request.term, request.leader_id)
        # Append log entries if any exist
        if request.entries:
            for entry in request.entries:
                self.node.db.append_raft_log(entry.term, entry.operation_type, entry.data)
        return raft_pb2.AppendEntriesResponse(
            term=self.node.current_term,
            success=True
        )


    def RequestState(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("State transfer not implemented")
        return raft_pb2.StateChunk()
