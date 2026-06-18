#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Collaboration Manager - Gestion de la collaboration en temps réel
"""

import uuid
import time
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import threading

@dataclass
class Collaborator:
    """Représente un collaborateur"""
    id: str
    name: str
    color: str
    connected_at: float
    last_seen: float

@dataclass
class Annotation:
    """Annotation sur un flow"""
    id: str
    flow_id: str
    author_id: str
    author_name: str
    content: str
    created_at: float
    updated_at: float

@dataclass
class SharedSession:
    """Session partagée"""
    id: str
    name: str
    owner_id: str
    target_url: str
    created_at: float
    collaborators: Dict[str, Collaborator]
    annotations: Dict[str, List[Annotation]]
    selected_flows: Dict[str, str]  # collaborator_id -> flow_id
    shared_flows: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    chat_messages: List[Dict[str, Any]] = field(default_factory=list)
    active_mirrors: Set[str] = field(default_factory=set)

class CollaborationManager:
    """Gère les sessions collaboratives et la synchronisation"""
    
    def __init__(self):
        self.sessions: Dict[str, SharedSession] = {}
        self.active_connections: Dict[str, Set[str]] = defaultdict(set)  # session_id -> set of websocket_ids
        self.websocket_to_session: Dict[str, str] = {}  # websocket_id -> session_id
        self.websocket_to_collaborator: Dict[str, str] = {}  # websocket_id -> collaborator_id
        self.lock = threading.Lock()
    
    def create_session(
        self,
        name: str,
        owner_id: str,
        target_url: str = "",
        session_id: Optional[str] = None,
    ) -> SharedSession:
        """Crée une nouvelle session partagée"""
        session_id = (session_id or str(uuid.uuid4())).strip()
        session = SharedSession(
            id=session_id,
            name=name,
            owner_id=owner_id,
            target_url=target_url,
            created_at=time.time(),
            collaborators={},
            annotations=defaultdict(list),
            selected_flows={},
        )
        
        with self.lock:
            self.sessions[session_id] = session
        
        return session
    
    def join_session(self, session_id: str, collaborator: Collaborator, websocket_id: str) -> Optional[SharedSession]:
        """Rejoint une session"""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            session.collaborators[collaborator.id] = collaborator
            self.active_connections[session_id].add(websocket_id)
            self.websocket_to_session[websocket_id] = session_id
            self.websocket_to_collaborator[websocket_id] = collaborator.id
        
        return session
    
    def leave_session(self, websocket_id: str):
        """Quitte une session"""
        with self.lock:
            session_id = self.websocket_to_session.get(websocket_id)
            if not session_id:
                return
            
            collaborator_id = self.websocket_to_collaborator.get(websocket_id)
            session = self.sessions.get(session_id)
            
            if session and collaborator_id:
                # Retirer le collaborateur
                if collaborator_id in session.collaborators:
                    del session.collaborators[collaborator_id]
                
                # Retirer la sélection
                if collaborator_id in session.selected_flows:
                    del session.selected_flows[collaborator_id]

                session.active_mirrors.discard(collaborator_id)
            
            # Nettoyer les connexions
            if session_id in self.active_connections:
                self.active_connections[session_id].discard(websocket_id)
            
            del self.websocket_to_session[websocket_id]
            if websocket_id in self.websocket_to_collaborator:
                del self.websocket_to_collaborator[websocket_id]
    
    def add_annotation(self, session_id: str, flow_id: str, author_id: str, author_name: str, content: str) -> Optional[Annotation]:
        """Ajoute une annotation"""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            annotation = Annotation(
                id=str(uuid.uuid4()),
                flow_id=flow_id,
                author_id=author_id,
                author_name=author_name,
                content=content,
                created_at=time.time(),
                updated_at=time.time()
            )
            
            session.annotations[flow_id].append(annotation)
        
        return annotation
    
    def update_annotation(self, session_id: str, annotation_id: str, author_id: str, content: str) -> Optional[Annotation]:
        """Met à jour une annotation"""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return None
            
            for flow_id, annotations in session.annotations.items():
                for annotation in annotations:
                    if annotation.id == annotation_id and annotation.author_id == author_id:
                        annotation.content = content
                        annotation.updated_at = time.time()
                        return annotation
        
        return None
    
    def delete_annotation(self, session_id: str, annotation_id: str, author_id: str) -> bool:
        """Supprime une annotation"""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            for flow_id, annotations in list(session.annotations.items()):
                for i, annotation in enumerate(annotations):
                    if annotation.id == annotation_id and annotation.author_id == author_id:
                        annotations.pop(i)
                        if not annotations:
                            del session.annotations[flow_id]
                        return True
        
        return False
    
    def set_selected_flow(self, session_id: str, collaborator_id: str, flow_id: str):
        """Définit le flow sélectionné par un collaborateur"""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            
            session.selected_flows[collaborator_id] = flow_id
    
    def get_session(self, session_id: str) -> Optional[SharedSession]:
        """Récupère une session"""
        with self.lock:
            return self.sessions.get(session_id)

    def get_session_by_invite(self, code: str) -> Optional[SharedSession]:
        """Résout une session par ID complet ou préfixe (code d'invitation)."""
        code = (code or "").strip().lower()
        if not code:
            return None
        with self.lock:
            session = self.sessions.get(code)
            if session:
                return session
            for sid, session in self.sessions.items():
                sid_lower = sid.lower()
                if sid_lower == code or sid_lower.startswith(code):
                    return session
        return None

    def add_shared_flow(self, session_id: str, flow: Dict[str, Any], user_id: Optional[str] = None) -> None:
        """Enregistre un flow partagé dans la session."""
        flow_id = flow.get("id")
        if not flow_id:
            return
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            stored = dict(flow)
            if user_id:
                stored["shared_by_user_id"] = user_id
                stored["user_id"] = user_id
            session.shared_flows[flow_id] = stored

    def add_chat_message(self, session_id: str, message: Dict[str, Any], max_messages: int = 200) -> None:
        """Ajoute un message de chat à l'historique de la session."""
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            session.chat_messages.append(message)
            if len(session.chat_messages) > max_messages:
                session.chat_messages = session.chat_messages[-max_messages:]

    def set_mirror_active(self, session_id: str, user_id: str, active: bool) -> None:
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return
            if active:
                session.active_mirrors.add(user_id)
            else:
                session.active_mirrors.discard(user_id)

    def update_collaborator_name(self, session_id: str, user_id: str, new_name: str) -> bool:
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            collaborator = session.collaborators.get(user_id)
            if not collaborator:
                return False
            collaborator.name = new_name
            return True
    
    def get_active_connections(self, session_id: str) -> Set[str]:
        """Récupère les IDs des connexions actives pour une session"""
        with self.lock:
            return self.active_connections.get(session_id, set()).copy()
    
    def get_collaborator_for_websocket(self, websocket_id: str) -> Optional[str]:
        """Récupère l'ID du collaborateur pour un websocket"""
        with self.lock:
            return self.websocket_to_collaborator.get(websocket_id)
    
    def get_session_for_websocket(self, websocket_id: str) -> Optional[str]:
        """Récupère l'ID de la session pour un websocket"""
        with self.lock:
            return self.websocket_to_session.get(websocket_id)
    
    def list_sessions(self) -> List[Dict]:
        """Liste toutes les sessions"""
        with self.lock:
            return [
                {
                    'id': session.id,
                    'name': session.name,
                    'owner_id': session.owner_id,
                    'target_url': session.target_url,
                    'collaborators_count': len(session.collaborators),
                    'created_at': session.created_at
                }
                for session in self.sessions.values()
            ]

# Instance globale
collaboration_manager = CollaborationManager()

