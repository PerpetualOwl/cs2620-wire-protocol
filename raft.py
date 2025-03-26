import grpc
import random
import threading
import time
from concurrent import futures
from enum import Enum
from typing import Dict, List, Optional, Tuple
import logging

import raft_pb2
import raft_pb2_grpc
from config import Config, ServerConfig
from database import DatabaseManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NodeState(Enum):
    FOLLOWER = 1
    CANDIDATE = 2
    LEADER = 3

class RaftNode:
    def __init__(self, server_id: str, config: Config, db: DatabaseManager):
        self.id = server_id
        self.config = config
        self.db = db
        
        # Volatile state
        self.state = NodeState.FOLLOWER
        self.current_term = 0
        self.voted_for = None
        self.leader_id = None
        self.last_heartbeat = 0
        
        # Load persistent state
        self._load_persistent_state()
        
        # Initialize locks
        self.state_lock = threading.Lock()
        self.vote_lock = threading.Lock()
        
        # Initialize gRPC stubs for other servers
        self.other_servers = {
            s.id: s for s in config.server_list if s.id != server_id
        }
        self.stubs = {}
        self._init_stubs()
        
        # If we're the only server, become leader immediately
        if len(self.config.servers) == 1:
            logger.info("Single server mode detected, becoming leader immediately")
            self.state = NodeState.LEADER
            self.leader_id = self.id
            # No need for election timer in single-server mode
            self.election_timer = None
        else:
            # Start election timer for multi-server mode
            self.election_timer = threading.Timer(
                self._get_election_timeout() / 1000,
                self._start_election
            )
            self.election_timer.start()
        
    def _load_persistent_state(self):
        """Load persistent state from storage"""
        term = self.db.get_raft_state('current_term')
        if term is not None:
            self.current_term = term
            
        voted_for = self.db.get_raft_state('voted_for')
        if voted_for is not None:
            self.voted_for = voted_for
            
    def _save_persistent_state(self):
        """Save persistent state to storage"""
        self.db.save_raft_state('current_term', self.current_term)
        self.db.save_raft_state('voted_for', self.voted_for)
        
    def _init_stubs(self):
        """Initialize gRPC stubs for other servers"""
        for server_id, server in self.other_servers.items():
            channel = grpc.insecure_channel(server.address)
            self.stubs[server_id] = raft_pb2_grpc.RaftServiceStub(channel)
            
    def _get_election_timeout(self) -> int:
        """Get random election timeout in milliseconds"""
        return random.randint(
            self.config.election_timeout_min,
            self.config.election_timeout_max
        )
        
    def _reset_election_timer(self):
        """Reset the election timer"""
        self.election_timer.cancel()
        self.election_timer = threading.Timer(
            self._get_election_timeout() / 1000,
            self._start_election
        )
        self.election_timer.start()
        
    def _start_election(self):
        """Start a new election"""
        with self.state_lock:
            if self.state == NodeState.LEADER:
                return
                
            # Become candidate
            self.state = NodeState.CANDIDATE
            self.current_term += 1
            self.voted_for = self.id
            self._save_persistent_state()
            
            # Get last log info
            last_log_index, last_log_term = self.db.get_last_log_entry()
            
            # Prepare request
            request = raft_pb2.RequestVoteRequest(
                term=self.current_term,
                candidate_id=self.id,
                last_log_index=last_log_index,
                last_log_term=last_log_term
            )
            
            # Request votes from all other servers
            votes_received = 1  # Vote for self
            for server_id, stub in self.stubs.items():
                try:
                    response = stub.RequestVote(request)
                    if response.vote_granted:
                        votes_received += 1
                except grpc.RpcError:
                    continue
                    
            # Check if we won the election
            if votes_received > len(self.config.servers) / 2:
                self._become_leader()
            else:
                self.state = NodeState.FOLLOWER
                self._reset_election_timer()
                
    def _become_leader(self):
        """Transition to leader state"""
        with self.state_lock:
            self.state = NodeState.LEADER
            self.leader_id = self.id
            logger.info(f"Node {self.id} became leader for term {self.current_term}")
            
            # Start sending heartbeats
            self._send_heartbeats()
            
    def _send_heartbeats(self):
        """Send heartbeats to all followers"""
        if self.state != NodeState.LEADER:
            return
            
        for server_id, stub in self.stubs.items():
            try:
                request = raft_pb2.AppendEntriesRequest(
                    term=self.current_term,
                    leader_id=self.id,
                    prev_log_index=0,  # Simplified for heartbeat
                    prev_log_term=0,   # Simplified for heartbeat
                    entries=[],         # Empty for heartbeat
                    leader_commit=0     # Simplified for heartbeat
                )
                response = stub.AppendEntries(request)
                
                if response.term > self.current_term:
                    self._step_down(response.term)
                    return
                    
            except grpc.RpcError:
                continue
                
        # Schedule next heartbeat if still leader
        if self.state == NodeState.LEADER:
            threading.Timer(
                self.config.heartbeat_interval / 1000,
                self._send_heartbeats
            ).start()
            
    def _step_down(self, term: int):
        """Step down as leader/candidate"""
        with self.state_lock:
            self.current_term = term
            self.state = NodeState.FOLLOWER
            self.voted_for = None
            self._save_persistent_state()
            self._reset_election_timer()
            
    def replicate_log(self, operation_type: str, data: bytes) -> bool:
        """Replicate a log entry to followers"""
        if self.state != NodeState.LEADER:
            logger.warning(f"Cannot replicate log: not a leader (current state: {self.state})")
            return False
            
        # Append to local log
        index = self.db.append_raft_log(self.current_term, operation_type, data)
        logger.info(f"Appended log entry {index} of type {operation_type}")
        
        # If we're the only server, apply immediately and return success
        if len(self.config.servers) == 1:
            logger.info("Single server mode detected, applying log entry immediately")
            # Apply the log entry to the state machine
            entry = self.db.get_raft_log_entry(index)
            if entry:
                success = self.apply_log_entry(entry)
                logger.info(f"Applied log entry in single server mode: {success}")
                return success
            else:
                logger.error(f"Failed to retrieve log entry {index}")
                return False
        
        # Replicate to followers in multi-server mode
        success_count = 1  # Count self
        logger.info(f"Replicating to {len(self.stubs)} followers")
        for server_id, stub in self.stubs.items():
            try:
                request = raft_pb2.LogEntry(
                    term=self.current_term,
                    index=index,
                    data=data,
                    operation_type=operation_type
                )
                response = stub.ReplicateLog(request)
                if response.success:
                    success_count += 1
                    logger.info(f"Server {server_id} successfully replicated log entry")
                else:
                    logger.warning(f"Server {server_id} failed to replicate log entry")
            except grpc.RpcError as e:
                logger.error(f"Error replicating to server {server_id}: {e}")
                continue
                
        # Check if we got majority
        majority = success_count > len(self.config.servers) / 2
        logger.info(f"Replication result: {success_count}/{len(self.config.servers)} servers, majority: {majority}")
        return majority
        
    def apply_log_entry(self, entry: Dict) -> bool:
        """Apply a log entry to the state machine"""
        try:
            logger.info(f"Applying log entry: {entry['operation_type']}")
            # Apply the operation based on type
            if entry['operation_type'] == 'CREATE_USER':
                data = entry['data'].decode()
                logger.info(f"Decoded data: {data}")
                username, password_hash = data.split(':')
                logger.info(f"Creating user: {username}")
                result = self.db.create_user(username, password_hash)
                logger.info(f"User creation result: {result}")
                return result
            elif entry['operation_type'] == 'DELETE_USER':
                username = entry['data'].decode()
                logger.info(f"Deleting user: {username}")
                result = self.db.delete_user(username)
                logger.info(f"User deletion result: {result}")
                return result
            elif entry['operation_type'] == 'SAVE_MESSAGE':
                data = entry['data'].decode()
                msg_id, sender, recipient, content, timestamp = data.split(':')
                logger.info(f"Saving message from {sender} to {recipient}")
                result = self.db.save_message(
                    msg_id, sender, recipient, content, int(timestamp)
                )
                logger.info(f"Message save result: {result}")
                return result
            elif entry['operation_type'] == 'DELETE_MESSAGES':
                message_ids = entry['data'].decode().split(',')
                logger.info(f"Deleting messages: {message_ids}")
                self.db.delete_messages(message_ids)
                return True
            else:
                logger.error(f"Unknown operation type: {entry['operation_type']}")
                return False
        except Exception as e:
            logger.error(f"Error applying log entry: {e}")
            logger.exception("Detailed exception information:")
            return False
            
class RaftService(raft_pb2_grpc.RaftServiceServicer):
    def __init__(self, node: RaftNode):
        self.node = node
        
    def RequestVote(self, request, context):
        with self.node.vote_lock:
            if request.term < self.node.current_term:
                return raft_pb2.RequestVoteResponse(
                    term=self.node.current_term,
                    vote_granted=False
                )
                
            if request.term > self.node.current_term:
                self.node._step_down(request.term)
                
            # Check if we've already voted
            if (self.node.voted_for is None or 
                self.node.voted_for == request.candidate_id):
                
                # Check if candidate's log is up-to-date
                last_log_index, last_log_term = self.node.db.get_last_log_entry()
                if (request.last_log_term > last_log_term or
                    (request.last_log_term == last_log_term and
                     request.last_log_index >= last_log_index)):
                    
                    self.node.voted_for = request.candidate_id
                    self.node._save_persistent_state()
                    return raft_pb2.RequestVoteResponse(
                        term=self.node.current_term,
                        vote_granted=True
                    )
                    
            return raft_pb2.RequestVoteResponse(
                term=self.node.current_term,
                vote_granted=False
            )
            
    def AppendEntries(self, request, context):
        if request.term < self.node.current_term:
            return raft_pb2.AppendEntriesResponse(
                term=self.node.current_term,
                success=False
            )
            
        if request.term > self.node.current_term:
            self.node._step_down(request.term)
            
        # Update leader
        self.node.leader_id = request.leader_id
        self.node.last_heartbeat = time.time()
        self.node._reset_election_timer()
        
        # Process log entries
        if request.entries:
            # Check previous log entry
            prev_entry = self.node.db.get_raft_log_entry(request.prev_log_index)
            if (prev_entry is None or 
                prev_entry['term'] != request.prev_log_term):
                return raft_pb2.AppendEntriesResponse(
                    term=self.node.current_term,
                    success=False
                )
                
            # Delete conflicting entries and append new ones
            self.node.db.delete_logs_from(request.prev_log_index + 1)
            for entry in request.entries:
                self.node.db.append_raft_log(
                    entry.term,
                    entry.operation_type,
                    entry.data
                )
                
        return raft_pb2.AppendEntriesResponse(
            term=self.node.current_term,
            success=True
        )
        
    def ReplicateLog(self, request, context):
        # Only accept log entries from current leader
        if (self.node.leader_id is None or
            request.term != self.node.current_term):
            return raft_pb2.ReplicationResponse(
                success=False,
                error_message="Not current leader"
            )
            
        try:
            # Append to log
            self.node.db.append_raft_log(
                request.term,
                request.operation_type,
                request.data
            )
            
            # Apply the entry
            entry = {
                'term': request.term,
                'operation_type': request.operation_type,
                'data': request.data
            }
            if self.node.apply_log_entry(entry):
                return raft_pb2.ReplicationResponse(success=True)
            else:
                return raft_pb2.ReplicationResponse(
                    success=False,
                    error_message="Failed to apply log entry"
                )
        except Exception as e:
            return raft_pb2.ReplicationResponse(
                success=False,
                error_message=str(e)
            )
            
    def RequestState(self, request, context):
        # TODO: Implement state transfer for new servers
        pass 